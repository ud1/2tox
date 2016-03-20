/* Messenger.c
 *
 * An implementation of a simple text chat only messenger on the tox network core.
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef DEBUG
#include <assert.h>
#endif

#include "logger.hpp"
#include "Messenger.hpp"
#include "assoc.hpp"
#include "network.hpp"
#include "util.hpp"

using namespace bitox;
using namespace bitox::network;
using namespace bitox::dht;

/*  return the friend id associated to that public key.
 *  return -1 if no such friend.
 */
int32_t Messenger::getfriend_id(const PublicKey &real_pk) const
{
    for (auto &kv : friends)
    {
        if (kv.second.status > 0)
            if (real_pk == kv.second.real_pk)
                return kv.first;
    }

    return -1;
}

Friend *Messenger::get_friend(const bitox::PublicKey &real_pk)
{
    for (auto &kv : friends)
    {
        if (kv.second.status > 0)
            if (real_pk == kv.second.real_pk)
                return &kv.second;
    }

    return nullptr;
}

Friend *Messenger::get_friend(uint32_t id)
{
    auto it = friends.find(id);
    if (it != friends.end())
        return &it->second;
    
    return nullptr;
}

const Friend *Messenger::get_friend(uint32_t id) const
{
    return const_cast<const Friend *>(const_cast<Messenger *>(this)->get_friend(id));
}

/*  return friend connection id on success.
 *  return -1 if failure.
 */
std::shared_ptr<Friend_Conn> Messenger::getfriendcon_id(int32_t friendnumber) const
{
    const Friend *f = get_friend(friendnumber);
    if (!f)
        return std::shared_ptr<Friend_Conn>();

    return f->friend_connection;
}

/*
 *  return a uint16_t that represents the checksum of address of length len.
 */
static uint16_t address_checksum(const uint8_t *address, uint32_t len)
{
    uint8_t checksum[2] = {0};
    uint16_t check;
    uint32_t i;

    for (i = 0; i < len; ++i)
        checksum[i % 2] ^= address[i];

    memcpy(&check, checksum, sizeof(check));
    return check;
}

/* Format: [real_pk (32 bytes)][nospam number (4 bytes)][checksum (2 bytes)]
 *
 *  return FRIEND_ADDRESS_SIZE byte address to give to others.
 */
void Messenger::getaddress(uint8_t *address) const
{
    id_copy(address, net_crypto->self_public_key.data.data());
    uint32_t nospam = get_nospam(&fr);
    memcpy(address + crypto_box_PUBLICKEYBYTES, &nospam, sizeof(nospam));
    uint16_t checksum = address_checksum(address, FRIEND_ADDRESS_SIZE - sizeof(checksum));
    memcpy(address + crypto_box_PUBLICKEYBYTES + sizeof(nospam), &checksum, sizeof(checksum));
}

int Friend::send_online_packet()
{
    uint8_t packet = PACKET_ID_ONLINE;
    return friend_connection->write_cryptpacket(&packet, sizeof(packet), 0) != -1;
}

static int send_offline_packet(Messenger *m, Friend_Conn *friend_connection)
{
    uint8_t packet = PACKET_ID_OFFLINE;
    return friend_connection->write_cryptpacket(&packet, sizeof(packet), 0) != -1;
}

Friend::Friend(Messenger *messenger, uint32_t id) : messenger(messenger), id(id)
{
    
}

static int32_t init_new_friend(Messenger *m, const PublicKey &real_pk, uint8_t status)
{
    uint32_t id = m->id_pool.next();

    Friend &f = m->friends.emplace(std::piecewise_construct, std::forward_as_tuple(id), std::forward_as_tuple(m, id)).first->second;

    std::shared_ptr<Friend_Conn> friend_connection = m->fr_c->new_friend_connection(real_pk);

    if (!friend_connection)
    {
        m->id_pool.release(id);
        return FAERR_NOMEM;
    }

    uint32_t i;

    f.status = status;
    f.friend_connection = friend_connection;
    f.friendrequest_lastsent = 0;
    f.real_pk = real_pk;
    f.statusmessage_length = 0;
    f.userstatus = USERSTATUS_NONE;
    f.is_typing = 0;
    f.message_id = 0;
    friend_connection->event_listener = &f;

    if (friend_connection->status == FriendConnectionStatus::FRIENDCONN_STATUS_CONNECTED) {
        f.send_online_packet();
    }

    return id;
}

/*
 * Add a friend.
 * Set the data that will be sent along with friend request.
 * Address is the address of the friend (returned by getaddress of the friend you wish to add) it must be FRIEND_ADDRESS_SIZE bytes.
 * data is the data and length is the length.
 *
 *  return the friend number if success.
 *  return FA_TOOLONG if message length is too long.
 *  return FAERR_NOMESSAGE if no message (message length must be >= 1 byte).
 *  return FAERR_OWNKEY if user's own key.
 *  return FAERR_ALREADYSENT if friend request already sent or already a friend.
 *  return FAERR_BADCHECKSUM if bad checksum in address.
 *  return FAERR_SETNEWNOSPAM if the friend was already there but the nospam was different.
 *  (the nospam for that friend was set to the new one).
 *  return FAERR_NOMEM if increasing the friend list size fails.
 */
int32_t Messenger::m_addfriend(const uint8_t *address, const uint8_t *data, uint16_t length)
{
    if (length > MAX_FRIEND_REQUEST_DATA_SIZE)
        return FAERR_TOOLONG;

    PublicKey real_pk;
    id_copy(real_pk.data.data(), address);

    if (!public_key_valid(real_pk))
        return FAERR_BADCHECKSUM;

    uint16_t check, checksum = address_checksum(address, FRIEND_ADDRESS_SIZE - sizeof(checksum));
    memcpy(&check, address + crypto_box_PUBLICKEYBYTES + sizeof(uint32_t), sizeof(check));

    if (check != checksum)
        return FAERR_BADCHECKSUM;

    if (length < 1)
        return FAERR_NOMESSAGE;

    if (real_pk == net_crypto->self_public_key)
        return FAERR_OWNKEY;

    int32_t friend_id = getfriend_id(real_pk);

    if (friend_id != -1)
    {
        Friend *f = get_friend(friend_id);
        if (f->status >= FRIEND_CONFIRMED)
            return FAERR_ALREADYSENT;

        uint32_t nospam;
        memcpy(&nospam, address + crypto_box_PUBLICKEYBYTES, sizeof(nospam));

        if (f->friendrequest_nospam == nospam)
            return FAERR_ALREADYSENT;

        f->friendrequest_nospam = nospam;
        return FAERR_SETNEWNOSPAM;
    }

    int32_t ret = init_new_friend(this, real_pk, FRIEND_ADDED);

    if (ret < 0) {
        return ret;
    }
    
    Friend *f = get_friend(ret);

    f->friendrequest_timeout = FRIENDREQUEST_TIMEOUT;
    memcpy(f->info, data, length);
    f->info_size = length;
    memcpy(&(f->friendrequest_nospam), address + crypto_box_PUBLICKEYBYTES, sizeof(uint32_t));

    return ret;
}

int32_t Messenger::m_addfriend_norequest(const PublicKey &real_pk)
{
    if (getfriend_id(real_pk) != -1)
        return FAERR_ALREADYSENT;

    if (!public_key_valid(real_pk))
        return FAERR_BADCHECKSUM;

    if (real_pk == net_crypto->self_public_key)
        return FAERR_OWNKEY;

    return init_new_friend(this, real_pk, FRIEND_CONFIRMED);
}

int Friend::clear_receipts()
{
    struct Receipts *receipts = receipts_start;

    while (receipts) {
        struct Receipts *temp_r = receipts->next;
        free(receipts);
        receipts = temp_r;
    }

    receipts_start = nullptr;
    receipts_end = nullptr;
    return 0;
}

int Friend::add_receipt(uint32_t packet_num, uint32_t msg_id)
{
    Receipts *newReceipts = (Receipts *) calloc(1, sizeof(Receipts));

    if (!newReceipts)
        return -1;

    newReceipts->packet_num = packet_num;
    newReceipts->msg_id = msg_id;

    if (!receipts_start) {
        receipts_start = newReceipts;
    } else {
        receipts_end->next = newReceipts;
    }

    receipts_end = newReceipts;
    newReceipts->next = NULL;
    return 0;
}
/*
 * return -1 on failure.
 * return 0 if packet was received.
 */
int Friend::friend_received_packet(uint32_t number)
{
    return friend_connection->cryptpacket_received(number);
}

int Friend::do_receipts()
{
    struct Receipts *receipts = receipts_start;

    while (receipts) {
        struct Receipts *temp_r = receipts->next;

        if (friend_received_packet(receipts->packet_num) == -1)
            break;

        if (messenger->read_receipt)
            (*messenger->read_receipt)(this, receipts->msg_id, messenger->read_receipt_userdata);

        free(receipts);
        receipts_start = temp_r;
        receipts = temp_r;
    }

    if (!receipts_start)
        receipts_end = NULL;

    return 0;
}

/* Remove a friend.
 *
 *  return 0 if success.
 *  return -1 if failure.
 */
Friend::~Friend()
{
    if (messenger->friend_connectionstatuschange_internal)
        messenger->friend_connectionstatuschange_internal(this, 0, messenger->friend_connectionstatuschange_internal_userdata);

    clear_receipts();
    remove_request_received(&(messenger->fr), real_pk);
    friend_connection->event_listener = nullptr;

    if (friend_connection->status == FriendConnectionStatus::FRIENDCONN_STATUS_CONNECTED) {
        send_offline_packet(messenger, friend_connection.get());
    }

    friend_connection.reset();
}

int Messenger::delete_friend(uint32_t id)
{
    if (friends.count(id))
    {
        friends.erase(id);
        id_pool.release(id);
        return 0;
    }
    return -1;
}

int Friend::m_get_friend_connectionstatus() const
{
    if (status == FRIEND_ONLINE && friend_connection->crypt_connection) {
        bool direct_connected = false;
        unsigned int num_online_relays = 0;
        friend_connection->crypto_connection_status(&direct_connected, &num_online_relays);

        if (direct_connected) {
            return CONNECTION_UDP;
        } else {
            if (num_online_relays) {
                return CONNECTION_TCP;
            } else {
                return CONNECTION_UNKNOWN;
            }
        }
    } else {
        return CONNECTION_NONE;
    }
}

/* Send a message of type.
 *
 * return -1 if friend not valid.
 * return -2 if too large.
 * return -3 if friend not online.
 * return -4 if send failed (because queue is full).
 * return -5 if bad type.
 * return 0 if success.
 */
int Friend::m_send_message_generic(uint8_t type, const uint8_t *message, uint32_t length, uint32_t *message_id)
{
    if (type > MESSAGE_ACTION)
        return -5;

    if (length >= MAX_CRYPTO_DATA_SIZE)
        return -2;

    if (status != FRIEND_ONLINE)
        return -3;

    uint8_t packet[length + 1];
    packet[0] = type + PACKET_ID_MESSAGE;

    if (length != 0)
        memcpy(packet + 1, message, length);

    int64_t packet_num = friend_connection->write_cryptpacket(packet, length + 1, 0);

    if (packet_num == -1)
        return -4;

    uint32_t msg_id = ++this->message_id;

    add_receipt(packet_num, msg_id);

    if (message_id)
        *message_id = msg_id;

    return 0;
}

/* Send a name packet to friendnumber.
 * length is the length with the NULL terminator.
 */
int Friend::m_sendname(const uint8_t *name, uint16_t length)
{
    if (length > MAX_NAME_LENGTH)
        return 0;

    return write_cryptpacket_id(PACKET_ID_NICKNAME, name, length, 0);
}

/* Set the name and name_length of a friend.
 *
 *  return 0 if success.
 *  return -1 if failure.
 */
int Friend::setfriendname(const uint8_t *name, uint16_t length)
{
    if (length > MAX_NAME_LENGTH || length == 0)
        return -1;

    this->name = std::string((const char *)name, length);
    return 0;
}

/* Set our nickname
 * name must be a string of maximum MAX_NAME_LENGTH length.
 * length must be at least 1 byte.
 * length is the length of name with the NULL terminator.
 *
 *  return 0 if success.
 *  return -1 if failure.
 */
int Messenger::setname(const uint8_t *name, uint16_t length)
{
    if (length > MAX_NAME_LENGTH)
        return -1;

    if (this->name_length == length && (length == 0 || memcmp(name, this->name, length) == 0))
        return 0;

    if (length)
        memcpy(this->name, name, length);

    this->name_length = length;
    uint32_t i;

    for (auto &kv : this->friends)
        kv.second.name_sent = 0;

    return 0;
}

/* Get our nickname and put it in name.
 * name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH bytes.
 *
 *  return the length of the name.
 */
uint16_t Messenger::getself_name(uint8_t *name) const
{
    if (name == NULL) {
        return 0;
    }

    memcpy(name, this->name, this->name_length);

    return this->name_length;
}

/* Get name of friendnumber and put it in name.
 * name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH bytes.
 *
 *  return length of name if success.
 *  return -1 if failure.
 */
int Friend::getname(uint8_t *name) const
{
    memcpy(name, this->name.c_str(), this->name.size());
    return this->name.size();
}

int Friend::m_get_name_size() const
{
    return this->name.size();
}

int Messenger::m_get_self_name_size() const
{
    return name_length;
}

int Messenger::m_set_statusmessage(const uint8_t *status, uint16_t length)
{
    if (length > MAX_STATUSMESSAGE_LENGTH)
        return -1;

    if (statusmessage_length == length && (length == 0 || memcmp(statusmessage, status, length) == 0))
        return 0;

    if (length)
        memcpy(statusmessage, status, length);

    statusmessage_length = length;

    uint32_t i;

    for (auto &kv : friends)
        kv.second.statusmessage_sent = 0;
        
    return 0;
}

int Messenger::m_set_userstatus(uint8_t status)
{
    if (status >= USERSTATUS_INVALID)
        return -1;

    if (userstatus == status)
        return 0;

    userstatus = (USERSTATUS) status;
    uint32_t i;

    for (auto &kv : friends)
        kv.second.userstatus_sent = 0;
        
    return 0;
}

/* return the size of friendnumber's user status.
 * Guaranteed to be at most MAX_STATUSMESSAGE_LENGTH.
 */
int Friend::m_get_statusmessage_size() const
{
    return statusmessage_length;
}

/*  Copy the user status of friendnumber into buf, truncating if needed to maxlen
 *  bytes, use m_get_statusmessage_size to find out how much you need to allocate.
 */
int Friend::m_copy_statusmessage(uint8_t *buf, uint32_t maxlen) const
{
    int msglen = MIN(maxlen, statusmessage_length);

    memcpy(buf, statusmessage, msglen);
    memset(buf + msglen, 0, maxlen - msglen);
    return msglen;
}

/* return the size of friendnumber's user status.
 * Guaranteed to be at most MAX_STATUSMESSAGE_LENGTH.
 */
int Messenger::m_get_self_statusmessage_size() const
{
    return statusmessage_length;
}

int Messenger::m_copy_self_statusmessage(uint8_t *buf) const
{
    memcpy(buf, statusmessage, statusmessage_length);
    return statusmessage_length;
}

uint8_t Friend::m_get_userstatus() const
{
    uint8_t status = userstatus;

    if (status >= USERSTATUS_INVALID) {
        status = USERSTATUS_NONE;
    }

    return status;
}

uint8_t Messenger::m_get_self_userstatus() const
{
    return userstatus;
}

uint64_t Friend::m_get_last_online() const
{
    return last_seen_time;
}

int Friend::m_set_usertyping(uint8_t is_typing)

{
    if (is_typing != 0 && is_typing != 1)
        return -1;

    if (user_istyping == is_typing)
        return 0;

    user_istyping = is_typing;
    user_istyping_sent = 0;

    return 0;
}

int Friend::m_get_istyping() const
{
    return is_typing;
}

int Friend::send_statusmessage(const uint8_t *status, uint16_t length)
{
    return write_cryptpacket_id(PACKET_ID_STATUSMESSAGE, status, length, 0);
}

int Friend::send_userstatus(uint8_t status)
{
    return write_cryptpacket_id(PACKET_ID_USERSTATUS, &status, sizeof(status), 0);
}

int Friend::send_user_istyping(uint8_t is_typing)
{
    uint8_t typing = is_typing;
    return write_cryptpacket_id(PACKET_ID_TYPING, &typing, sizeof(typing), 0);
}

int Friend::set_friend_statusmessage(const uint8_t *status, uint16_t length)
{
    if (length > MAX_STATUSMESSAGE_LENGTH)
        return -1;

    if (length)
        memcpy(statusmessage, status, length);

    statusmessage_length = length;
    return 0;
}

void Friend::set_friend_userstatus(uint8_t status)
{
    userstatus = (USERSTATUS) status;
}

void Friend::set_friend_typing(uint8_t is_typing)
{
    this->is_typing = is_typing;
}

/* Set the function that will be executed when a friend request is received. */
void m_callback_friendrequest(Messenger *m, void (*function)(Messenger *m, const uint8_t *, const uint8_t *, size_t,
                              void *), void *userdata)
{
    void (*handle_friendrequest)(void *, const uint8_t *, const uint8_t *, size_t, void *) = (void (*)(void*, const uint8_t*, const uint8_t*, size_t, void*))function;
    callback_friendrequest(&(m->fr), handle_friendrequest, m, userdata);
}

/* Set the function that will be executed when a message from a friend is received. */
void m_callback_friendmessage(Messenger *m, void (*function)(Friend *, unsigned int, const uint8_t *,
                              size_t, void *), void *userdata)
{
    m->friend_message = function;
    m->friend_message_userdata = userdata;
}

void m_callback_namechange(Messenger *m, void (*function)(Friend *, const uint8_t *, size_t, void *),
                           void *userdata)
{
    m->friend_namechange = function;
    m->friend_namechange_userdata = userdata;
}

void m_callback_statusmessage(Messenger *m, void (*function)(Friend *, const uint8_t *, size_t, void *),
                              void *userdata)
{
    m->friend_statusmessagechange = function;
    m->friend_statusmessagechange_userdata = userdata;
}

void m_callback_userstatus(Messenger *m, void (*function)(Friend *, unsigned int, void *), void *userdata)
{
    m->friend_userstatuschange = function;
    m->friend_userstatuschange_userdata = userdata;
}

void m_callback_typingchange(Messenger *m, void(*function)(Friend *, bool, void *), void *userdata)
{
    m->friend_typingchange = function;
    m->friend_typingchange_userdata = userdata;
}

void m_callback_read_receipt(Messenger *m, void (*function)(Friend *, uint32_t, void *), void *userdata)
{
    m->read_receipt = function;
    m->read_receipt_userdata = userdata;
}

void m_callback_connectionstatus(Messenger *m, void (*function)(Friend *, unsigned int, void *),
                                 void *userdata)
{
    m->friend_connectionstatuschange = function;
    m->friend_connectionstatuschange_userdata = userdata;
}

void m_callback_core_connection(Messenger *m, void (*function)(Messenger *m, unsigned int, void *), void *userdata)
{
    m->core_connection_change = function;
    m->core_connection_change_userdata = userdata;
}

void m_callback_connectionstatus_internal_av(Messenger *m, void (*function)(Friend *, uint8_t, void *),
        void *userdata)
{
    m->friend_connectionstatuschange_internal = function;
    m->friend_connectionstatuschange_internal_userdata = userdata;
}

void Friend::check_friend_tcp_udp()
{
    int ret = m_get_friend_connectionstatus();

    if (ret == -1)
        return;

    if (ret == CONNECTION_UNKNOWN) {
        if (last_connection_udp_tcp == CONNECTION_UDP) {
            return;
        } else {
            ret = CONNECTION_TCP;
        }
    }

    if (last_connection_udp_tcp != ret) {
        if (messenger->friend_connectionstatuschange)
            messenger->friend_connectionstatuschange(this, ret, messenger->friend_connectionstatuschange_userdata);
    }

    last_connection_udp_tcp = ret;
}

void Friend::check_friend_connectionstatus(uint8_t status)
{
    if (status == NOFRIEND)
        return;

    const uint8_t was_online = this->status == FRIEND_ONLINE;
    const uint8_t is_online = status == FRIEND_ONLINE;

    if (is_online != was_online) {
        if (was_online) {
            break_files();
            clear_receipts();
        } else {
            this->name_sent = 0;
            this->userstatus_sent = 0;
            this->statusmessage_sent = 0;
            this->user_istyping_sent = 0;
        }

        this->status = status;

        check_friend_tcp_udp();

        if (messenger->friend_connectionstatuschange_internal)
            messenger->friend_connectionstatuschange_internal(this, is_online,
                    messenger->friend_connectionstatuschange_internal_userdata);
    }
}

void Friend::set_friend_status(uint8_t status)
{
    check_friend_connectionstatus(status);
    this->status = status;
}

int Friend::write_cryptpacket_id(uint8_t packet_id, const uint8_t *data,
                                uint32_t length, uint8_t congestion_control)
{
    if (length >= MAX_CRYPTO_DATA_SIZE || status != FRIEND_ONLINE)
        return 0;

    uint8_t packet[length + 1];
    packet[0] = packet_id;

    if (length != 0)
        memcpy(packet + 1, data, length);

    return friend_connection->write_cryptpacket(packet, length + 1, congestion_control) != -1;
}

/**********GROUP CHATS************/


/* Set the callback for group invites.
 *
 *  Function(Friend * friendnumber, uint8_t *data, uint16_t length)
 */
void m_callback_group_invite(Messenger *m, void (*function)(Friend *, const uint8_t *, uint16_t))
{
    m->group_invite = function;
}


/* Send a group invite packet.
 *
 *  return 1 on success
 *  return 0 on failure
 */
int Friend::send_group_invite_packet(const uint8_t *data, uint16_t length)
{
    return write_cryptpacket_id(PACKET_ID_INVITE_GROUPCHAT, data, length, 0);
}

/****************FILE SENDING*****************/


/* Set the callback for file send requests.
 *
 *  Function(Tox *tox, uint32_t friendnumber, uint32_t filenumber, uint32_t filetype, uint64_t filesize, uint8_t *filename, size_t filename_length, void *userdata)
 */
void callback_file_sendrequest(Messenger *m, void (*function)(Friend *, uint32_t, uint32_t, uint64_t,
                               const uint8_t *, size_t, void *), void *userdata)
{
    m->file_sendrequest = function;
    m->file_sendrequest_userdata = userdata;
}

/* Set the callback for file control requests.
 *
 *  Function(Tox *tox, uint32_t friendnumber, uint32_t filenumber, unsigned int control_type, void *userdata)
 *
 */
void callback_file_control(Messenger *m, void (*function)(Friend *, uint32_t, unsigned int, void *),
                           void *userdata)
{
    m->file_filecontrol = function;
    m->file_filecontrol_userdata = userdata;
}

/* Set the callback for file data.
 *
 *  Function(Tox *tox, uint32_t friendnumber, uint32_t filenumber, uint64_t position, uint8_t *data, size_t length, void *userdata)
 *
 */
void callback_file_data(Messenger *m, void (*function)(Friend *, uint32_t, uint64_t, const uint8_t *,
                        size_t, void *), void *userdata)
{
    m->file_filedata = function;
    m->file_filedata_userdata = userdata;
}

/* Set the callback for file request chunk.
 *
 *  Function(Tox *tox, uint32_t friendnumber, uint32_t filenumber, uint64_t position, size_t length, void *userdata)
 *
 */
void callback_file_reqchunk(Messenger *m, void (*function)(Friend *, uint32_t, uint64_t, size_t, void *),
                            void *userdata)
{
    m->file_reqchunk = function;
    m->file_reqchunk_userdata = userdata;
}

#define MAX_FILENAME_LENGTH 255

/* Copy the file transfer file id to file_id
 *
 * return 0 on success.
 * return -1 if friend not valid.
 * return -2 if filenumber not valid
 */
int Friend::file_get_id(uint32_t filenumber, uint8_t *file_id) const
{
    if (status != FRIEND_ONLINE)
        return -2;

    uint32_t temp_filenum;
    uint8_t send_receive, file_number;

    if (filenumber >= (1 << 16)) {
        send_receive = 1;
        temp_filenum = (filenumber >> 16) - 1;
    } else {
        send_receive = 0;
        temp_filenum = filenumber;
    }

    if (temp_filenum >= MAX_CONCURRENT_FILE_PIPES)
        return -2;

    file_number = temp_filenum;

    const File_Transfers *ft;

    if (send_receive) {
        ft = &file_receiving[file_number];
    } else {
        ft = &file_sending[file_number];
    }

    if (ft->status == FileStatus::FILESTATUS_NONE)
        return -2;

    memcpy(file_id, ft->id, FILE_ID_LENGTH);
    return 0;
}

/* Send a file send request.
 * Maximum filename length is 255 bytes.
 *  return 1 on success
 *  return 0 on failure
 */
int Friend::file_sendrequest(uint8_t filenumber, uint32_t file_type,
                            uint64_t filesize, const uint8_t *file_id, const uint8_t *filename, uint16_t filename_length)
{
    if (filename_length > MAX_FILENAME_LENGTH)
        return 0;

    uint8_t packet[1 + sizeof(file_type) + sizeof(filesize) + FILE_ID_LENGTH + filename_length];
    packet[0] = filenumber;
    file_type = htonl(file_type);
    memcpy(packet + 1, &file_type, sizeof(file_type));
    host_to_net((uint8_t *)&filesize, sizeof(filesize));
    memcpy(packet + 1 + sizeof(file_type), &filesize, sizeof(filesize));
    memcpy(packet + 1 + sizeof(file_type) + sizeof(filesize), file_id, FILE_ID_LENGTH);

    if (filename_length) {
        memcpy(packet + 1 + sizeof(file_type) + sizeof(filesize) + FILE_ID_LENGTH, filename, filename_length);
    }

    return write_cryptpacket_id(PACKET_ID_FILE_SENDREQUEST, packet, sizeof(packet), 0);
}

/* Send a file send request.
 * Maximum filename length is 255 bytes.
 *  return file number on success
 *  return -1 if friend not found.
 *  return -2 if filename length invalid.
 *  return -3 if no more file sending slots left.
 *  return -4 if could not send packet (friend offline).
 *
 */
long int Friend::new_filesender(uint32_t file_type, uint64_t filesize,
                        const uint8_t *file_id, const uint8_t *filename, uint16_t filename_length)
{
    if (filename_length > MAX_FILENAME_LENGTH)
        return -2;

    uint32_t i;

    for (i = 0; i < MAX_CONCURRENT_FILE_PIPES; ++i) {
        if (file_sending[i].status == FileStatus::FILESTATUS_NONE)
            break;
    }

    if (i == MAX_CONCURRENT_FILE_PIPES)
        return -3;

    if (file_sendrequest(i, file_type, filesize, file_id, filename, filename_length) == 0)
        return -4;

    struct File_Transfers *ft = &file_sending[i];
    ft->status = FileStatus::FILESTATUS_NOT_ACCEPTED;
    ft->size = filesize;
    ft->transferred = 0;
    ft->requested = 0;
    ft->slots_allocated = 0;
    ft->paused = FILE_PAUSE_NOT;
    memcpy(ft->id, file_id, FILE_ID_LENGTH);

    ++num_sending_files;

    return i;
}

int Friend::send_file_control_packet(uint8_t send_receive, uint8_t filenumber,
                             uint8_t control_type, uint8_t *data, uint16_t data_length)
{
    if ((unsigned int)(1 + 3 + data_length) > MAX_CRYPTO_DATA_SIZE)
        return -1;

    uint8_t packet[3 + data_length];

    packet[0] = send_receive;
    packet[1] = filenumber;
    packet[2] = control_type;

    if (data_length) {
        memcpy(packet + 3, data, data_length);
    }

    return write_cryptpacket_id(PACKET_ID_FILE_CONTROL, packet, sizeof(packet), 0);
}

/* Send a file control request.
 *
 *  return 0 on success
 *  return -1 if friend not valid.
 *  return -2 if friend not online.
 *  return -3 if file number invalid.
 *  return -4 if file control is bad.
 *  return -5 if file already paused.
 *  return -6 if resume file failed because it was only paused by the other.
 *  return -7 if resume file failed because it wasn't paused.
 *  return -8 if packet failed to send.
 */
int Friend::file_control(uint32_t filenumber, unsigned int control)
{
    if (status != FRIEND_ONLINE)
        return -2;

    uint32_t temp_filenum;
    uint8_t send_receive, file_number;

    if (filenumber >= (1 << 16)) {
        send_receive = 1;
        temp_filenum = (filenumber >> 16) - 1;
    } else {
        send_receive = 0;
        temp_filenum = filenumber;
    }

    if (temp_filenum >= MAX_CONCURRENT_FILE_PIPES)
        return -3;

    file_number = temp_filenum;

    struct File_Transfers *ft;

    if (send_receive) {
        ft = &file_receiving[file_number];
    } else {
        ft = &file_sending[file_number];
    }

    if (ft->status == FileStatus::FILESTATUS_NONE)
        return -3;

    if (control > FILECONTROL_KILL)
        return -4;

    if (control == FILECONTROL_PAUSE && ((ft->paused & FILE_PAUSE_US) || ft->status != FileStatus::FILESTATUS_TRANSFERRING))
        return -5;

    if (control == FILECONTROL_ACCEPT) {
        if (ft->status == FileStatus::FILESTATUS_TRANSFERRING) {
            if (!(ft->paused & FILE_PAUSE_US)) {
                if (ft->paused & FILE_PAUSE_OTHER) {
                    return -6;
                } else {
                    return -7;
                }
            }
        } else {
            if (ft->status != FileStatus::FILESTATUS_NOT_ACCEPTED)
                return -7;

            if (!send_receive)
                return -6;
        }
    }

    if (send_file_control_packet(send_receive, file_number, control, 0, 0)) {
        if (control == FILECONTROL_KILL) {
            ft->status = FileStatus::FILESTATUS_NONE;

            if (send_receive == 0) {
                --num_sending_files;
            }
        } else if (control == FILECONTROL_PAUSE) {
            ft->paused |= FILE_PAUSE_US;
        } else if (control == FILECONTROL_ACCEPT) {
            ft->status = FileStatus::FILESTATUS_TRANSFERRING;

            if (ft->paused & FILE_PAUSE_US) {
                ft->paused ^=  FILE_PAUSE_US;
            }
        }
    } else {
        return -8;
    }

    return 0;
}

/* Send a seek file control request.
 *
 *  return 0 on success
 *  return -1 if friend not valid.
 *  return -2 if friend not online.
 *  return -3 if file number invalid.
 *  return -4 if not receiving file.
 *  return -5 if file status wrong.
 *  return -6 if position bad.
 *  return -8 if packet failed to send.
 */
int Friend::file_seek(uint32_t filenumber, uint64_t position)
{
    if (status != FRIEND_ONLINE)
        return -2;

    uint32_t temp_filenum;
    uint8_t send_receive, file_number;

    if (filenumber >= (1 << 16)) {
        send_receive = 1;
        temp_filenum = (filenumber >> 16) - 1;
    } else {
        return -4;
    }

    if (temp_filenum >= MAX_CONCURRENT_FILE_PIPES)
        return -3;

    file_number = temp_filenum;

    struct File_Transfers *ft;

    if (send_receive) {
        ft = &file_receiving[file_number];
    } else {
        ft = &file_sending[file_number];
    }

    if (ft->status == FileStatus::FILESTATUS_NONE)
        return -3;

    if (ft->status != FileStatus::FILESTATUS_NOT_ACCEPTED)
        return -5;

    if (position >= ft->size) {
        return -6;
    }

    uint64_t sending_pos = position;
    host_to_net((uint8_t *)&sending_pos, sizeof(sending_pos));

    if (send_file_control_packet(send_receive, file_number, FILECONTROL_SEEK, (uint8_t *)&sending_pos,
                                 sizeof(sending_pos))) {
        ft->transferred = position;
    } else {
        return -8;
    }

    return 0;
}

/* return packet number on success.
 * return -1 on failure.
 */
int64_t Friend::send_file_data_packet(uint8_t filenumber, const uint8_t *data,
                                     uint16_t length) const
{
    uint8_t packet[2 + length];
    packet[0] = PACKET_ID_FILE_DATA;
    packet[1] = filenumber;

    if (length) {
        memcpy(packet + 2, data, length);
    }

    if (!friend_connection)
        return -1;
    
    return friend_connection->write_cryptpacket(packet, sizeof(packet), 1);
}

#define MAX_FILE_DATA_SIZE (MAX_CRYPTO_DATA_SIZE - 2)
#define MIN_SLOTS_FREE (CRYPTO_MIN_QUEUE_LENGTH / 4)
/* Send file data.
 *
 *  return 0 on success
 *  return -1 if friend not valid.
 *  return -2 if friend not online.
 *  return -3 if filenumber invalid.
 *  return -4 if file transfer not transferring.
 *  return -5 if bad data size.
 *  return -6 if packet queue full.
 *  return -7 if wrong position.
 */
int Friend::file_data(uint32_t filenumber, uint64_t position, const uint8_t *data,
              uint16_t length)
{
    if (status != FRIEND_ONLINE)
        return -2;

    if (filenumber >= MAX_CONCURRENT_FILE_PIPES)
        return -3;

    struct File_Transfers *ft = &file_sending[filenumber];

    if (ft->status != FileStatus::FILESTATUS_TRANSFERRING)
        return -4;

    if (length > MAX_FILE_DATA_SIZE)
        return -5;

    if (ft->size - ft->transferred < length) {
        return -5;
    }

    if (ft->size != UINT64_MAX && length != MAX_FILE_DATA_SIZE && (ft->transferred + length) != ft->size) {
        return -5;
    }

    if (position != ft->transferred || (ft->requested <= position && ft->size != 0)) {
        return -7;
    }

    /* Prevent file sending from filling up the entire buffer preventing messages from being sent. TODO: remove */
    if (friend_connection->crypto_num_free_sendqueue_slots() < MIN_SLOTS_FREE)
        return -6;

    int64_t ret = send_file_data_packet(filenumber, data, length);

    if (ret != -1) {
        //TODO record packet ids to check if other received complete file.
        ft->transferred += length;

        if (ft->slots_allocated) {
            --ft->slots_allocated;
        }

        if (length != MAX_FILE_DATA_SIZE || ft->size == ft->transferred) {
            ft->status = FileStatus::FILESTATUS_FINISHED;
            ft->last_packet_number = ret;
        }

        return 0;
    }

    return -6;

}

/* Give the number of bytes left to be sent/received.
 *
 *  send_receive is 0 if we want the sending files, 1 if we want the receiving.
 *
 *  return number of bytes remaining to be sent/received on success
 *  return 0 on failure
 */
uint64_t Friend::file_dataremaining(uint8_t filenumber, uint8_t send_receive)
{
    if (send_receive == 0) {
        if (file_sending[filenumber].status == FileStatus::FILESTATUS_NONE)
            return 0;

        return file_sending[filenumber].size -
               file_sending[filenumber].transferred;
    } else {
        if (file_receiving[filenumber].status == FileStatus::FILESTATUS_NONE)
            return 0;

        return file_receiving[filenumber].size -
               file_receiving[filenumber].transferred;
    }
}

void Friend::do_reqchunk_filecb()
{
    if (!num_sending_files)
        return;

    int free_slots = friend_connection->crypto_num_free_sendqueue_slots();

    if (free_slots < MIN_SLOTS_FREE) {
        free_slots = 0;
    } else {
        free_slots -= MIN_SLOTS_FREE;
    }

    unsigned int i, num = num_sending_files;

    for (i = 0; i < MAX_CONCURRENT_FILE_PIPES; ++i) {
        struct File_Transfers *ft = &file_sending[i];

        if (ft->status != FileStatus::FILESTATUS_NONE) {
            --num;

            if (ft->status == FileStatus::FILESTATUS_FINISHED) {
                /* Check if file was entirely sent. */
                if (friend_received_packet(ft->last_packet_number) == 0) {
                    if (messenger->file_reqchunk)
                        (*messenger->file_reqchunk)(this, i, ft->transferred, 0, messenger->file_reqchunk_userdata);

                    ft->status = FileStatus::FILESTATUS_NONE;
                    --num_sending_files;
                }
            }

            /* TODO: if file is too slow, switch to the next. */
            if (ft->slots_allocated > (unsigned int)free_slots) {
                free_slots = 0;
            } else {
                free_slots -= ft->slots_allocated;
            }
        }

        while (ft->status == FileStatus::FILESTATUS_TRANSFERRING && (ft->paused == FILE_PAUSE_NOT)) {
            if (friend_connection->max_speed_reached() != 0) {
                free_slots = 0;
            }

            if (free_slots == 0)
                break;

            uint16_t length = MAX_FILE_DATA_SIZE;

            if (ft->size == 0) {
                /* Send 0 data to friend if file is 0 length. */
                file_data(i, 0, 0, 0);
                break;
            }

            if (ft->size == ft->requested) {
                break;
            }

            if (ft->size - ft->requested < length) {
                length = ft->size - ft->requested;
            }

            ++ft->slots_allocated;

            uint64_t position = ft->requested;
            ft->requested += length;

            if (messenger->file_reqchunk)
                (*messenger->file_reqchunk)(this, i, position, length, messenger->file_reqchunk_userdata);

            --free_slots;

        }

        if (num == 0)
            break;
    }
}

/* Run this when the friend disconnects.
 *  Kill all current file transfers.
 */
void Friend::break_files()
{
    uint32_t i;

    //TODO: Inform the client which file transfers get killed with a callback?
    for (i = 0; i < MAX_CONCURRENT_FILE_PIPES; ++i) {
        if (file_sending[i].status != FileStatus::FILESTATUS_NONE)
            file_sending[i].status = FileStatus::FILESTATUS_NONE;

        if (file_receiving[i].status != FileStatus::FILESTATUS_NONE)
            file_receiving[i].status = FileStatus::FILESTATUS_NONE;
    }
}

/* return -1 on failure, 0 on success.
 */
int Friend::handle_filecontrol(uint8_t receive_send, uint8_t filenumber,
                              uint8_t control_type, uint8_t *data, uint16_t length)
{
    if (receive_send > 1)
        return -1;

    if (control_type > FILECONTROL_SEEK)
        return -1;

    uint32_t real_filenumber = filenumber;
    struct File_Transfers *ft;

    if (receive_send == 0) {
        real_filenumber += 1;
        real_filenumber <<= 16;
        ft = &file_receiving[filenumber];
    } else {
        ft = &file_sending[filenumber];
    }

    if (ft->status == FileStatus::FILESTATUS_NONE) {
        /* File transfer doesn't exist, tell the other to kill it. */
        send_file_control_packet(!receive_send, filenumber, FILECONTROL_KILL, 0, 0);
        return -1;
    }

    if (control_type == FILECONTROL_ACCEPT) {
        if (receive_send && ft->status == FileStatus::FILESTATUS_NOT_ACCEPTED) {
            ft->status = FileStatus::FILESTATUS_TRANSFERRING;
        } else {
            if (ft->paused & FILE_PAUSE_OTHER) {
                ft->paused ^= FILE_PAUSE_OTHER;
            } else {
                return -1;
            }
        }

        if (messenger->file_filecontrol)
            (*messenger->file_filecontrol)(this, real_filenumber, control_type, messenger->file_filecontrol_userdata);
    } else if (control_type == FILECONTROL_PAUSE) {
        if ((ft->paused & FILE_PAUSE_OTHER) || ft->status != FileStatus::FILESTATUS_TRANSFERRING) {
            return -1;
        }

        ft->paused |= FILE_PAUSE_OTHER;

        if (messenger->file_filecontrol)
            (*messenger->file_filecontrol)(this, real_filenumber, control_type, messenger->file_filecontrol_userdata);
    } else if (control_type == FILECONTROL_KILL) {

        if (messenger->file_filecontrol)
            (*messenger->file_filecontrol)(this, real_filenumber, control_type, messenger->file_filecontrol_userdata);

        ft->status = FileStatus::FILESTATUS_NONE;

        if (receive_send) {
            --num_sending_files;
        }

    } else if (control_type == FILECONTROL_SEEK) {
        uint64_t position;

        if (length != sizeof(position)) {
            return -1;
        }

        /* seek can only be sent by the receiver to seek before resuming broken transfers. */
        if (ft->status != FileStatus::FILESTATUS_NOT_ACCEPTED || !receive_send) {
            return -1;
        }

        memcpy(&position, data, sizeof(position));
        net_to_host((uint8_t *) &position, sizeof(position));

        if (position >= ft->size) {
            return -1;
        }

        ft->transferred = ft->requested = position;
    } else {
        return -1;
    }

    return 0;
}

/**************************************/

/* Set the callback for msi packets.
 *
 *  Function(Messenger *m, int friendnumber, uint8_t *data, uint16_t length, void *userdata)
 */
void m_callback_msi_packet(Messenger *m, void (*function)(Friend *, const uint8_t *, uint16_t, void *),
                           void *userdata)
{
    m->msi_packet = function;
    m->msi_packet_userdata = userdata;
}

/* Send an msi packet.
 *
 *  return 1 on success
 *  return 0 on failure
 */
int Friend::m_msi_packet(const uint8_t *data, uint16_t length)
{
    return write_cryptpacket_id(PACKET_ID_MSI, data, length, 0);
}

int Friend::on_lossy_data(uint8_t *packet, uint16_t length)
{
    if (packet[0] < (PACKET_ID_LOSSY_RANGE_START + PACKET_LOSSY_AV_RESERVED)) {
        if (lossy_rtp_packethandlers[packet[0] % PACKET_LOSSY_AV_RESERVED].function)
            return lossy_rtp_packethandlers[packet[0] % PACKET_LOSSY_AV_RESERVED].function(
                       this, packet, length, lossy_rtp_packethandlers[packet[0] %
                               PACKET_LOSSY_AV_RESERVED].object);

        return 1;
    }

    if (messenger->lossy_packethandler)
        messenger->lossy_packethandler(this, packet, length, messenger->lossy_packethandler_userdata);

    return 1;
}

void custom_lossy_packet_registerhandler(Messenger *m, void (*packet_handler_callback)(Friend *, const uint8_t *data, size_t len, void *object), void *object)
{
    m->lossy_packethandler = packet_handler_callback;
    m->lossy_packethandler_userdata = object;
}

int m_callback_rtp_packet(Messenger *m, int32_t friendnumber, uint8_t byte, int (*packet_handler_callback)(Friend *, const uint8_t *data, uint16_t len, void *object), void *object)
{
    if (byte < PACKET_ID_LOSSY_RANGE_START)
        return -1;

    if (byte >= (PACKET_ID_LOSSY_RANGE_START + PACKET_LOSSY_AV_RESERVED))
        return -1;

    Friend *f = m->get_friend(friendnumber);
    f->lossy_rtp_packethandlers[byte % PACKET_LOSSY_AV_RESERVED].function =
        packet_handler_callback;
    f->lossy_rtp_packethandlers[byte % PACKET_LOSSY_AV_RESERVED].object = object;
    return 0;
}


int Friend::send_custom_lossy_packet(const uint8_t *data, uint32_t length)
{
    if (length == 0 || length > MAX_CRYPTO_DATA_SIZE)
        return -2;

    if (data[0] < PACKET_ID_LOSSY_RANGE_START)
        return -3;

    if (data[0] >= (PACKET_ID_LOSSY_RANGE_START + PACKET_ID_LOSSY_RANGE_SIZE))
        return -3;

    if (status != FRIEND_ONLINE)
        return -4;

    if (!friend_connection->send_lossy_cryptpacket(data, length) == -1)
    {
        return -5;
    }
    else
    {
        return 0;
    }
}

static int handle_custom_lossless_packet(void *object, int friend_num, const uint8_t *packet, uint16_t length)
{
    Messenger *m = (Messenger *) object;

    if (packet[0] < PACKET_ID_LOSSLESS_RANGE_START)
        return -1;

    if (packet[0] >= (PACKET_ID_LOSSLESS_RANGE_START + PACKET_ID_LOSSLESS_RANGE_SIZE))
        return -1;

    if (m->lossless_packethandler)
        m->lossless_packethandler(m->get_friend(friend_num), packet, length, m->lossless_packethandler_userdata);

    return 1;
}

void custom_lossless_packet_registerhandler(Messenger *m, void (*packet_handler_callback)(Friend *, const uint8_t *data, size_t len, void *object), void *object)
{
    m->lossless_packethandler = packet_handler_callback;
    m->lossless_packethandler_userdata = object;
}

int Friend::send_custom_lossless_packet(const uint8_t *data, uint32_t length) const
{
    if (length == 0 || length > MAX_CRYPTO_DATA_SIZE)
        return -2;

    if (data[0] < PACKET_ID_LOSSLESS_RANGE_START)
        return -3;

    if (data[0] >= (PACKET_ID_LOSSLESS_RANGE_START + PACKET_ID_LOSSLESS_RANGE_SIZE))
        return -3;

    if (status != FRIEND_ONLINE)
        return -4;

    if (friend_connection->write_cryptpacket(data, length, 1) == -1) {
        return -5;
    } else {
        return 0;
    }
}

/* Function to filter out some friend requests*/
static int friend_already_added(const PublicKey &real_pk, void *data)
{
    const Messenger *m = (const Messenger *) data;

    if (m->getfriend_id(real_pk) == -1)
        return 0;

    return -1;
}

/* Run this at startup. */
Messenger::Messenger(Messenger_Options *options)
{
    unsigned int net_err = 0;

    //crypto_manager = TODO
    event_dispatcher = std::unique_ptr<EventDispatcher>(new EventDispatcher(*crypto_manager.get()));
    if (options->udp_disabled) {
        /* this is the easiest way to completely disable UDP without changing too much code. */
        net = new Networking_Core(event_dispatcher.get());
    } else {
        IP ip;
        ip_init(&ip, options->ipv6enabled);
        net = new_networking_ex(ip, options->port_range[0], options->port_range[1], &net_err, event_dispatcher.get());
    }

    dht = std::unique_ptr<DHT>(new DHT(net, event_dispatcher.get()));

    // TODO kill_networking ?

    net_crypto = std::unique_ptr<Net_Crypto>(new Net_Crypto(dht.get(), &options->proxy_info, event_dispatcher.get()));

    onion = std::unique_ptr<Onion>(new Onion(*dht, event_dispatcher.get()));
    onion_a = std::unique_ptr<Onion_Announce>(new Onion_Announce(dht.get(), event_dispatcher.get()));
    onion_c = std::unique_ptr<Onion_Client>(new Onion_Client(net_crypto.get(), event_dispatcher.get()));
    fr_c = std::unique_ptr<Friend_Connections>(new Friend_Connections(onion_c.get()));

    if (options->tcp_server_port) {
        tcp_server = std::unique_ptr<TCP_Server>(new TCP_Server(options->ipv6enabled, 1, &options->tcp_server_port, dht->self_secret_key, onion.get()));
    }

    this->options = *options;
    friendreq_init(&fr, fr_c.get());
    set_nospam(&fr, random_int());
    set_filter_function(&fr, &friend_already_added, this);
}

/* Run this before closing shop. */
Messenger::~Messenger()
{
    uint32_t i;

    kill_networking(net);

    for (auto &kv : friends)
        kv.second.clear_receipts();
}

/* Check for and handle a timed-out friend request. If the request has
 * timed-out then the friend status is set back to FRIEND_ADDED.
 *   i: friendlist index of the timed-out friend
 *   t: time
 */
void Friend::check_friend_request_timed_out(uint64_t t)
{
    if (friendrequest_lastsent + friendrequest_timeout < t) {
        set_friend_status(FRIEND_ADDED);
        /* Double the default timeout every time if friendrequest is assumed
         * to have been sent unsuccessfully.
         */
        friendrequest_timeout *= 2;
    }
}

int Friend::on_status(uint8_t status)
{
    if (status) { /* Went online. */
        send_online_packet();
    } else { /* Went offline. */
        if (status == FRIEND_ONLINE) {
            set_friend_status(FRIEND_CONFIRMED);
        }
    }

    return 0;
}

int Friend::on_data(uint8_t *temp, uint16_t length)
{
    if (length == 0)
        return -1;

    uint8_t packet_id = temp[0];
    uint8_t *data = temp + 1;
    uint32_t data_length = length - 1;

    if (status != FRIEND_ONLINE) {
        if (packet_id == PACKET_ID_ONLINE && length == 1) {
            set_friend_status(FRIEND_ONLINE);
            send_online_packet();
        } else {
            return -1;
        }
    }

    switch (packet_id) {
        case PACKET_ID_OFFLINE: {
            if (data_length != 0)
                break;

            set_friend_status(FRIEND_CONFIRMED);
            break;
        }

        case PACKET_ID_NICKNAME: {
            if (data_length > MAX_NAME_LENGTH)
                break;

            /* Make sure the NULL terminator is present. */
            uint8_t data_terminated[data_length + 1];
            memcpy(data_terminated, data, data_length);
            data_terminated[data_length] = 0;

            /* inform of namechange before we overwrite the old name */
            if (messenger->friend_namechange)
                messenger->friend_namechange(this, data_terminated, data_length, messenger->friend_namechange_userdata);

            name = std::string((const char *) data_terminated, data_length);
            break;
        }

        case PACKET_ID_STATUSMESSAGE: {
            if (data_length > MAX_STATUSMESSAGE_LENGTH)
                break;

            /* Make sure the NULL terminator is present. */
            uint8_t data_terminated[data_length + 1];
            memcpy(data_terminated, data, data_length);
            data_terminated[data_length] = 0;

            if (messenger->friend_statusmessagechange)
                messenger->friend_statusmessagechange(this, data_terminated, data_length,
                                              messenger->friend_statusmessagechange_userdata);

            set_friend_statusmessage(data_terminated, data_length);
            break;
        }

        case PACKET_ID_USERSTATUS: {
            if (data_length != 1)
                break;

            USERSTATUS status = (USERSTATUS) data[0];

            if (status >= USERSTATUS_INVALID)
                break;

            if (messenger->friend_userstatuschange)
                messenger->friend_userstatuschange(this, status, messenger->friend_userstatuschange_userdata);

            set_friend_userstatus(status);
            break;
        }

        case PACKET_ID_TYPING: {
            if (data_length != 1)
                break;

            bool typing = !!data[0];

            set_friend_typing(typing);

            if (messenger->friend_typingchange)
                messenger->friend_typingchange(this, typing, messenger->friend_typingchange_userdata);

            break;
        }

        case PACKET_ID_MESSAGE:
        case PACKET_ID_ACTION: {
            if (data_length == 0)
                break;

            const uint8_t *message = data;
            uint16_t message_length = data_length;

            /* Make sure the NULL terminator is present. */
            uint8_t message_terminated[message_length + 1];
            memcpy(message_terminated, message, message_length);
            message_terminated[message_length] = 0;
            uint8_t type = packet_id - PACKET_ID_MESSAGE;

            if (messenger->friend_message)
                (*messenger->friend_message)(this, type, message_terminated, message_length, messenger->friend_message_userdata);

            break;
        }

        case PACKET_ID_INVITE_GROUPCHAT: {
            if (data_length == 0)
                break;

            if (messenger->group_invite)
                (*messenger->group_invite)(this, data, data_length);

            break;
        }

        case PACKET_ID_FILE_SENDREQUEST: {
            const unsigned int head_length = 1 + sizeof(uint32_t) + sizeof(uint64_t) + FILE_ID_LENGTH;

            if (data_length < head_length)
                break;

            uint8_t filenumber = data[0];

            if (filenumber >= MAX_CONCURRENT_FILE_PIPES)
                break;

            uint64_t filesize;
            uint32_t file_type;
            uint16_t filename_length = data_length - head_length;

            if (filename_length > MAX_FILENAME_LENGTH)
                break;

            memcpy(&file_type, data + 1, sizeof(file_type));
            file_type = ntohl(file_type);

            memcpy(&filesize, data + 1 + sizeof(uint32_t), sizeof(filesize));
            net_to_host((uint8_t *) &filesize, sizeof(filesize));
            struct File_Transfers *ft = &file_receiving[filenumber];

            if (ft->status != FileStatus::FILESTATUS_NONE)
                break;

            ft->status = FileStatus::FILESTATUS_NOT_ACCEPTED;
            ft->size = filesize;
            ft->transferred = 0;
            ft->paused = FILE_PAUSE_NOT;
            memcpy(ft->id, data + 1 + sizeof(uint32_t) + sizeof(uint64_t), FILE_ID_LENGTH);

            uint8_t filename_terminated[filename_length + 1];
            uint8_t *filename = NULL;

            if (filename_length) {
                /* Force NULL terminate file name. */
                memcpy(filename_terminated, data + head_length, filename_length);
                filename_terminated[filename_length] = 0;
                filename = filename_terminated;
            }

            uint32_t real_filenumber = filenumber;
            real_filenumber += 1;
            real_filenumber <<= 16;

            if (messenger->file_sendrequest)
                (*messenger->file_sendrequest)(this, real_filenumber, file_type, filesize, filename, filename_length,
                                       messenger->file_sendrequest_userdata);

            break;
        }

        case PACKET_ID_FILE_CONTROL: {
            if (data_length < 3)
                break;

            uint8_t send_receive = data[0];
            uint8_t filenumber = data[1];
            uint8_t control_type = data[2];

            if (filenumber >= MAX_CONCURRENT_FILE_PIPES)
                break;

            if (handle_filecontrol(send_receive, filenumber, control_type, data + 3, data_length - 3) == -1)
                break;

            break;
        }

        case PACKET_ID_FILE_DATA: {
            if (data_length < 1)
                break;

            uint8_t filenumber = data[0];

            if (filenumber >= MAX_CONCURRENT_FILE_PIPES)
                break;

            struct File_Transfers *ft = &file_receiving[filenumber];

            if (ft->status != FileStatus::FILESTATUS_TRANSFERRING)
                break;

            uint64_t position = ft->transferred;
            uint32_t real_filenumber = filenumber;
            real_filenumber += 1;
            real_filenumber <<= 16;
            uint16_t file_data_length = (data_length - 1);
            uint8_t *file_data;

            if (file_data_length == 0) {
                file_data = NULL;
            } else {
                file_data = data + 1;
            }

            /* Prevent more data than the filesize from being passed to clients. */
            if ((ft->transferred + file_data_length) > ft->size) {
                file_data_length = ft->size - ft->transferred;
            }

            if (messenger->file_filedata)
                (*messenger->file_filedata)(this, real_filenumber, position, file_data, file_data_length, messenger->file_filedata_userdata);

            ft->transferred += file_data_length;

            if (file_data_length && (ft->transferred >= ft->size || file_data_length != MAX_FILE_DATA_SIZE)) {
                file_data_length = 0;
                file_data = NULL;
                position = ft->transferred;

                /* Full file received. */
                if (messenger->file_filedata)
                    (*messenger->file_filedata)(this, real_filenumber, position, file_data, file_data_length, messenger->file_filedata_userdata);
            }

            /* Data is zero, filetransfer is over. */
            if (file_data_length == 0) {
                ft->status = FileStatus::FILESTATUS_NONE;
            }

            break;
        }

        case PACKET_ID_MSI: {
            if (data_length == 0)
                break;

            if (messenger->msi_packet)
                (*messenger->msi_packet)(this, data, data_length, messenger->msi_packet_userdata);

            break;
        }

        default: {
            on_lossy_data(temp, length);
            break;
        }
    }

    return 0;
}

void Messenger::do_friends()
{
    uint32_t i;
    uint64_t temp_time = unix_time();

    for (auto &kv : friends) {
        Friend &f = kv.second;
        
        if (f.status == FRIEND_ADDED && f.friend_connection) {
            int fr = f.friend_connection->send_friend_request_packet(f.friendrequest_nospam,
                                                f.info,
                                                f.info_size);

            if (fr >= 0) {
                f.set_friend_status(FRIEND_REQUESTED);
                f.friendrequest_lastsent = temp_time;
            }
        }

        if (f.status == FRIEND_REQUESTED
                || f.status == FRIEND_CONFIRMED) { /* friend is not online. */
            if (f.status == FRIEND_REQUESTED) {
                /* If we didn't connect to friend after successfully sending him a friend request the request is deemed
                 * unsuccessful so we set the status back to FRIEND_ADDED and try again.
                 */
                f.check_friend_request_timed_out(temp_time);
            }
        }

        if (f.status == FRIEND_ONLINE) { /* friend is online. */
            if (f.name_sent == 0) {
                if (f.m_sendname(name, name_length))
                    f.name_sent = 1;
            }

            if (f.statusmessage_sent == 0) {
                if (f.send_statusmessage(statusmessage, statusmessage_length))
                    f.statusmessage_sent = 1;
            }

            if (f.userstatus_sent == 0) {
                if (f.send_userstatus(userstatus))
                    f.userstatus_sent = 1;
            }

            if (f.user_istyping_sent == 0) {
                if (f.send_user_istyping(f.user_istyping))
                    f.user_istyping_sent = 1;
            }

            f.check_friend_tcp_udp();
            f.do_receipts();
            f.do_reqchunk_filecb();

            f.last_seen_time = (uint64_t) time(NULL);
        }
    }
}

void Messenger::connection_status_cb()
{
    unsigned int conn_status = onion_c->onion_connection_status();

    if (conn_status != last_connection_status) {
        if (core_connection_change)
            (*core_connection_change)(this, conn_status, core_connection_change_userdata);

        last_connection_status = conn_status;
    }
}


#ifdef TOX_LOGGER
#define DUMPING_CLIENTS_FRIENDS_EVERY_N_SECONDS 60UL
static time_t lastdump = 0;
static char IDString[crypto_box_PUBLICKEYBYTES * 2 + 1];
static char *ID2String(const uint8_t *pk)
{
    uint32_t i;

    for (i = 0; i < crypto_box_PUBLICKEYBYTES; i++)
        sprintf(&IDString[i * 2], "%02X", pk[i]);

    IDString[crypto_box_PUBLICKEYBYTES * 2] = 0;
    return IDString;
}
#endif

/* Minimum messenger run interval in ms
   TODO: A/V */
#define MIN_RUN_INTERVAL 50

/* Return the time in milliseconds before do_messenger() should be called again
 * for optimal performance.
 *
 * returns time (in ms) before the next do_messenger() needs to be run on success.
 */
uint32_t Messenger::messenger_run_interval() const
{
    uint32_t crypto_interval = net_crypto->crypto_run_interval();

    if (crypto_interval > MIN_RUN_INTERVAL) {
        return MIN_RUN_INTERVAL;
    } else {
        return crypto_interval;
    }
}

/* The main loop that needs to be run at least 20 times per second. */
void Messenger::do_messenger()
{
    // Add the TCP relays, but only if this is the first time calling do_messenger
    if (!has_added_relays) {
        has_added_relays = true;

        for (size_t i = 0; i < NUM_SAVED_TCP_RELAYS; ++i) {
            net_crypto->add_tcp_relay(loaded_relays[i].ip_port, loaded_relays[i].public_key);
        }

        if (tcp_server) {
            /* Add self tcp server. */
            IPPort local_ip_port;
            local_ip_port.port = options.tcp_server_port;
            local_ip_port.ip.family = Family::FAMILY_AF_INET;
            local_ip_port.ip.address.from_string("127.0.0.1");
            net_crypto->add_tcp_relay(local_ip_port, tcp_server->public_key);
        }
    }

    unix_time_update();

    if (!options.udp_disabled) {
        net->poll();
        dht->do_DHT();
    }

    if (tcp_server) {
        tcp_server->do_TCP_server();
    }

    net_crypto->do_net_crypto();
    onion_c->do_onion_client();
    fr_c->do_friend_connections();
    do_friends();
    connection_status_cb();

#ifdef TOX_LOGGER

    if (unix_time() > lastdump + DUMPING_CLIENTS_FRIENDS_EVERY_N_SECONDS) {

#ifdef ENABLE_ASSOC_DHT
        Assoc_status(m->dht->assoc);
#endif

        lastdump = unix_time();
        uint32_t client, last_pinged;

        for (client = 0; client < LCLIENT_LIST; client++) {
            Client_data *cptr = &m->dht->close_clientlist[client];
            IPPTsPng *assoc = NULL;
            uint32_t a;

            for (a = 0, assoc = &cptr->assoc4; a < 2; a++, assoc = &cptr->assoc6)
                if (ip_isset(&assoc->ip_port.ip)) {
                    last_pinged = lastdump - assoc->last_pinged;

                    if (last_pinged > 999)
                        last_pinged = 999;

                    LOGGER_TRACE("C[%2u] %s:%u [%3u] %s",
                                 client, ip_ntoa(&assoc->ip_port.ip), ntohs(assoc->ip_port.port),
                                 last_pinged, ID2String(cptr->public_key));
                }
        }


        uint32_t friend, dhtfriend;

        /* dht contains additional "friends" (requests) */
        uint32_t num_dhtfriends = m->dht->num_friends;
        int32_t m2dht[num_dhtfriends];
        int32_t dht2m[num_dhtfriends];

        for (friend = 0; friend < num_dhtfriends; friend++) {
            m2dht[friend] = -1;
            dht2m[friend] = -1;

            if (friend >= m->numfriends)
                continue;

            for (dhtfriend = 0; dhtfriend < m->dht->num_friends; dhtfriend++)
                if (id_equal(m->friendlist[friend].real_pk, m->dht->friends_list[dhtfriend].public_key)) {
                    m2dht[friend] = dhtfriend;
                    break;
                }
        }

        for (friend = 0; friend < num_dhtfriends; friend++)
            if (m2dht[friend] >= 0)
                dht2m[m2dht[friend]] = friend;

        if (m->numfriends != m->dht->num_friends) {
            LOGGER_TRACE("Friend num in DHT %u != friend num in msger %u\n", m->dht->num_friends, m->numfriends);
        }

        Friend *msgfptr;
        DHT_Friend *dhtfptr;

        for (friend = 0; friend < num_dhtfriends; friend++) {
            if (dht2m[friend] >= 0)
                msgfptr = &m->friendlist[dht2m[friend]];
            else
                msgfptr = NULL;

            dhtfptr = &m->dht->friends_list[friend];

            if (msgfptr) {
                LOGGER_TRACE("F[%2u:%2u] <%s> %s",
                             dht2m[friend], friend, msgfptr->name,
                             ID2String(msgfptr->real_pk));
            } else {
                LOGGER_TRACE("F[--:%2u] %s", friend, ID2String(dhtfptr->public_key));
            }

            for (client = 0; client < MAX_FRIEND_CLIENTS; client++) {
                Client_data *cptr = &dhtfptr->client_list[client];
                IPPTsPng *assoc = NULL;
                uint32_t a;

                for (a = 0, assoc = &cptr->assoc4; a < 2; a++, assoc = &cptr->assoc6)
                    if (ip_isset(&assoc->ip_port.ip)) {
                        last_pinged = lastdump - assoc->last_pinged;

                        if (last_pinged > 999)
                            last_pinged = 999;

                        LOGGER_TRACE("F[%2u] => C[%2u] %s:%u [%3u] %s",
                                     friend, client, ip_ntoa(&assoc->ip_port.ip),
                                     ntohs(assoc->ip_port.port), last_pinged,
                                     ID2String(cptr->public_key));
                    }
            }
        }
    }

#endif /* TOX_LOGGER */
}

/* new messenger format for load/save, more robust and forward compatible */

#define MESSENGER_STATE_COOKIE_GLOBAL 0x15ed1b1f

#define MESSENGER_STATE_COOKIE_TYPE      0x01ce
#define MESSENGER_STATE_TYPE_NOSPAMKEYS    1
#define MESSENGER_STATE_TYPE_DHT           2
#define MESSENGER_STATE_TYPE_FRIENDS       3
#define MESSENGER_STATE_TYPE_NAME          4
#define MESSENGER_STATE_TYPE_STATUSMESSAGE 5
#define MESSENGER_STATE_TYPE_STATUS        6
#define MESSENGER_STATE_TYPE_TCP_RELAY     10
#define MESSENGER_STATE_TYPE_PATH_NODE     11
#define MESSENGER_STATE_TYPE_END           255

#define SAVED_FRIEND_REQUEST_SIZE 1024
#define NUM_SAVED_PATH_NODES 8
struct SAVED_FRIEND {
    uint8_t status;
    PublicKey real_pk;
    uint8_t info[SAVED_FRIEND_REQUEST_SIZE]; // the data that is sent during the friend requests we do.
    uint16_t info_size; // Length of the info.
    uint8_t name[MAX_NAME_LENGTH];
    uint16_t name_length;
    uint8_t statusmessage[MAX_STATUSMESSAGE_LENGTH];
    uint16_t statusmessage_length;
    uint8_t userstatus;
    uint32_t friendrequest_nospam;
    uint64_t last_seen_time;
};

uint32_t Messenger::saved_friendslist_size() const
{
    return count_friendlist() * sizeof(struct SAVED_FRIEND);
}

uint32_t Messenger::friends_list_save(uint8_t *data) const
{
    uint32_t num = 0;

    for (auto &kv : friends) {
        const Friend &f = kv.second;
        if (f.status > 0) {
            struct SAVED_FRIEND temp;
            memset(&temp, 0, sizeof(struct SAVED_FRIEND));
            temp.status = f.status;
            temp.real_pk = f.real_pk;

            if (temp.status < 3) {
                if (f.info_size > SAVED_FRIEND_REQUEST_SIZE) {
                    memcpy(temp.info, f.info, SAVED_FRIEND_REQUEST_SIZE);
                } else {
                    memcpy(temp.info, f.info, f.info_size);
                }

                temp.info_size = htons(f.info_size);
                temp.friendrequest_nospam = f.friendrequest_nospam;
            } else {
                memcpy(temp.name, f.name.c_str(), f.name.size());
                temp.name_length = htons(f.name.size());
                memcpy(temp.statusmessage, f.statusmessage, f.statusmessage_length);
                temp.statusmessage_length = htons(f.statusmessage_length);
                temp.userstatus = f.userstatus;

                uint8_t last_seen_time[sizeof(uint64_t)];
                memcpy(last_seen_time, &f.last_seen_time, sizeof(uint64_t));
                host_to_net(last_seen_time, sizeof(uint64_t));
                memcpy(&temp.last_seen_time, last_seen_time, sizeof(uint64_t));
            }

            memcpy(data + num * sizeof(struct SAVED_FRIEND), &temp, sizeof(struct SAVED_FRIEND));
            num++;
        }
    }

    return num * sizeof(struct SAVED_FRIEND);
}

static int friends_list_load(Messenger *m, const uint8_t *data, uint32_t length)
{
    if (length % sizeof(struct SAVED_FRIEND) != 0) {
        return -1;
    }

    uint32_t num = length / sizeof(struct SAVED_FRIEND);
    uint32_t i;

    for (i = 0; i < num; ++i) {
        struct SAVED_FRIEND temp;
        memcpy(&temp, data + i * sizeof(struct SAVED_FRIEND), sizeof(struct SAVED_FRIEND));

        if (temp.status >= 3) {
            int fnum = m->m_addfriend_norequest(temp.real_pk);

            if (fnum < 0)
                continue;
            
            Friend *f = m->get_friend(fnum);
            f->setfriendname(temp.name, ntohs(temp.name_length));
            f->set_friend_statusmessage(temp.statusmessage, ntohs(temp.statusmessage_length));
            f->set_friend_userstatus(temp.userstatus);
            uint8_t last_seen_time[sizeof(uint64_t)];
            memcpy(last_seen_time, &temp.last_seen_time, sizeof(uint64_t));
            net_to_host(last_seen_time, sizeof(uint64_t));
            memcpy(&f->last_seen_time, last_seen_time, sizeof(uint64_t));
        } else if (temp.status != 0) {
            /* TODO: This is not a good way to do this. */
            uint8_t address[FRIEND_ADDRESS_SIZE];
            id_copy(address, temp.real_pk.data.data());
            memcpy(address + crypto_box_PUBLICKEYBYTES, &(temp.friendrequest_nospam), sizeof(uint32_t));
            uint16_t checksum = address_checksum(address, FRIEND_ADDRESS_SIZE - sizeof(checksum));
            memcpy(address + crypto_box_PUBLICKEYBYTES + sizeof(uint32_t), &checksum, sizeof(checksum));
            m->m_addfriend(address, temp.info, ntohs(temp.info_size));
        }
    }

    return num;
}

/*  return size of the messenger data (for saving) */
uint32_t Messenger::messenger_size() const
{
    uint32_t size32 = sizeof(uint32_t), sizesubhead = size32 * 2;
    return   size32 * 2                                      // global cookie
             + sizesubhead + sizeof(uint32_t) + crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES
             + sizesubhead + dht->size()                  // DHT
             + sizesubhead + saved_friendslist_size()         // Friendlist itself.
             + sizesubhead + name_length                    // Own nickname.
             + sizesubhead + statusmessage_length           // status message
             + sizesubhead + 1                                 // status
             + sizesubhead + NUM_SAVED_TCP_RELAYS * packed_node_size(TCP_INET6) //TCP relays
             + sizesubhead + NUM_SAVED_PATH_NODES * packed_node_size(TCP_INET6) //saved path nodes
             + sizesubhead;
}

static uint8_t *z_state_save_subheader(uint8_t *data, uint32_t len, uint16_t type)
{
    host_to_lendian32(data, len);
    data += sizeof(uint32_t);
    host_to_lendian32(data, (host_tolendian16(MESSENGER_STATE_COOKIE_TYPE) << 16) | host_tolendian16(type));
    data += sizeof(uint32_t);
    return data;
}

/* Save the messenger in data of size Messenger_size(). */
void Messenger::messenger_save(uint8_t *data) const
{
    memset(data, 0, messenger_size());

    uint32_t len;
    uint16_t type;
    uint32_t size32 = sizeof(uint32_t);

    memset(data, 0, size32);
    data += size32;
    host_to_lendian32(data, MESSENGER_STATE_COOKIE_GLOBAL);
    data += size32;

#ifdef DEBUG
    assert(sizeof(get_nospam(&(m->fr))) == sizeof(uint32_t));
#endif
    len = size32 + crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES;
    type = MESSENGER_STATE_TYPE_NOSPAMKEYS;
    data = z_state_save_subheader(data, len, type);
    *(uint32_t *)data = get_nospam(&(fr));
    net_crypto->save_keys(data + size32);
    data += len;

    len = saved_friendslist_size();
    type = MESSENGER_STATE_TYPE_FRIENDS;
    data = z_state_save_subheader(data, len, type);
    friends_list_save(data);
    data += len;

    len = name_length;
    type = MESSENGER_STATE_TYPE_NAME;
    data = z_state_save_subheader(data, len, type);
    memcpy(data, name, len);
    data += len;

    len = statusmessage_length;
    type = MESSENGER_STATE_TYPE_STATUSMESSAGE;
    data = z_state_save_subheader(data, len, type);
    memcpy(data, statusmessage, len);
    data += len;

    len = 1;
    type = MESSENGER_STATE_TYPE_STATUS;
    data = z_state_save_subheader(data, len, type);
    *data = userstatus;
    data += len;

    len = dht->size();
    type = MESSENGER_STATE_TYPE_DHT;
    data = z_state_save_subheader(data, len, type);
    dht->save(data);
    data += len;

    NodeFormat relays[NUM_SAVED_TCP_RELAYS];
    type = MESSENGER_STATE_TYPE_TCP_RELAY;
    uint8_t *temp_data = data;
    data = z_state_save_subheader(temp_data, 0, type);
    unsigned int num = net_crypto->copy_connected_tcp_relays(relays, NUM_SAVED_TCP_RELAYS);
    int l = pack_nodes(data, NUM_SAVED_TCP_RELAYS * packed_node_size(TCP_INET6), relays, num);

    if (l > 0) {
        len = l;
        data = z_state_save_subheader(temp_data, len, type);
        data += len;
    }

    NodeFormat nodes[NUM_SAVED_PATH_NODES];
    type = MESSENGER_STATE_TYPE_PATH_NODE;
    temp_data = data;
    data = z_state_save_subheader(data, 0, type);
    memset(nodes, 0, sizeof(nodes));
    num = onion_c->onion_backup_nodes(nodes, NUM_SAVED_PATH_NODES);
    l = pack_nodes(data, NUM_SAVED_PATH_NODES * packed_node_size(TCP_INET6), nodes, num);

    if (l > 0) {
        len = l;
        data = z_state_save_subheader(temp_data, len, type);
        data += len;
    }

    z_state_save_subheader(data, 0, MESSENGER_STATE_TYPE_END);
}

static int messenger_load_state_callback(void *outer, const uint8_t *data, uint32_t length, uint16_t type)
{
    Messenger *m = (Messenger *) outer;

    switch (type) {
        case MESSENGER_STATE_TYPE_NOSPAMKEYS:
            if (length == crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + sizeof(uint32_t)) {
                set_nospam(&(m->fr), *(uint32_t *)data);
                m->net_crypto->load_secret_key((&data[sizeof(uint32_t)]) + crypto_box_PUBLICKEYBYTES);

                if (public_key_cmp((&data[sizeof(uint32_t)]), m->net_crypto->self_public_key.data.data()) != 0) {
                    return -1;
                }
            } else
                return -1;    /* critical */

            break;

        case MESSENGER_STATE_TYPE_DHT:
            m->dht->load(data, length);
            break;

        case MESSENGER_STATE_TYPE_FRIENDS:
            friends_list_load(m, data, length);
            break;

        case MESSENGER_STATE_TYPE_NAME:
            if ((length > 0) && (length <= MAX_NAME_LENGTH)) {
                m->setname(data, length);
            }

            break;

        case MESSENGER_STATE_TYPE_STATUSMESSAGE:
            if ((length > 0) && (length < MAX_STATUSMESSAGE_LENGTH)) {
                m->m_set_statusmessage(data, length);
            }

            break;

        case MESSENGER_STATE_TYPE_STATUS:
            if (length == 1) {
                m->m_set_userstatus(*data);
            }

            break;

        case MESSENGER_STATE_TYPE_TCP_RELAY: {
            if (length == 0) {
                break;
            }

            unpack_nodes(m->loaded_relays, Messenger::NUM_SAVED_TCP_RELAYS, 0, data, length, 1);
            m->has_added_relays = false;

            break;
        }

        case MESSENGER_STATE_TYPE_PATH_NODE: {
            NodeFormat nodes[NUM_SAVED_PATH_NODES];

            if (length == 0) {
                break;
            }

            int i, num = unpack_nodes(nodes, NUM_SAVED_PATH_NODES, 0, data, length, 0);

            for (i = 0; i < num; ++i) {
                m->onion_c->onion_add_bs_path_node(nodes[i].ip_port, nodes[i].public_key);
            }

            break;
        }

        case MESSENGER_STATE_TYPE_END: {
            if (length != 0) {
                return -1;
            }

            return -2;
            break;
        }

#ifdef DEBUG

        default:
            fprintf(stderr, "Load state: contains unrecognized part (len %u, type %u)\n",
                    length, type);
            break;
#endif
    }

    return 0;
}

/* Load the messenger from data of size length. */
int Messenger::messenger_load(const uint8_t *data, uint32_t length)
{
    uint32_t data32[2];
    uint32_t cookie_len = sizeof(data32);

    if (length < cookie_len)
        return -1;

    memcpy(data32, data, sizeof(uint32_t));
    lendian_to_host32(data32 + 1, data + sizeof(uint32_t));

    if (!data32[0] && (data32[1] == MESSENGER_STATE_COOKIE_GLOBAL))
        return load_state(messenger_load_state_callback, this, data + cookie_len,
                          length - cookie_len, MESSENGER_STATE_COOKIE_TYPE);
    else
        return -1;
}

/* Return the number of friends in the instance m.
 * You should use this to determine how much memory to allocate
 * for copy_friendlist. */
uint32_t Messenger::count_friendlist() const
{
    return friends.size();
}

/* Copy a list of valid friend IDs into the array out_list.
 * If out_list is NULL, returns 0.
 * Otherwise, returns the number of elements copied.
 * If the array was too small, the contents
 * of out_list will be truncated to list_size. */
uint32_t Messenger::copy_friendlist(uint32_t *out_list, uint32_t list_size) const
{
    if (!out_list)
        return 0;

    if (friends.empty()) {
        return 0;
    }

    uint32_t i;
    uint32_t ret = 0;

    for (auto &kv : friends) {
        const Friend &f = kv.second;
        if (ret >= list_size) {
            break; /* Abandon ship */
        }

        if (f.status > 0) {
            out_list[ret] = i;
            ret++;
        }
    }

    return ret;
}
