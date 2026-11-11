/* <!-- copyright */
/*
 * aria2 - The high speed download utility
 *
 * Copyright (C) 2013 Tatsuhiro Tsujikawa
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */
/* copyright --> */
#include "ConnectCommand.h"
#include "BackupIPv4ConnectCommand.h"
#include "ControlChain.h"
#include "Option.h"
#include "message.h"
#include "SocketCore.h"
#include "fmt.h"
#include "LogFactory.h"
#include "DownloadEngine.h"
#include "Request.h"
#include "prefs.h"
#include "SocketRecvBuffer.h"
#include "DlAbortEx.h"
#include "DlRetryEx.h"

#include <algorithm>
#include <array>

namespace aria2 {

ConnectCommand::ConnectCommand(cuid_t cuid, const std::shared_ptr<Request>& req,
                               const std::shared_ptr<Request>& proxyRequest,
                               const std::shared_ptr<FileEntry>& fileEntry,
                               RequestGroup* requestGroup, DownloadEngine* e,
                               const std::shared_ptr<SocketCore>& s)
    : AbstractCommand(cuid, req, fileEntry, requestGroup, e, s),
      proxyRequest_(proxyRequest)
{
  setTimeout(std::chrono::seconds(getOption()->getAsInt(PREF_CONNECT_TIMEOUT)));
  disableReadCheckSocket();
  setWriteCheckSocket(getSocket());
}

ConnectCommand::~ConnectCommand()
{
  if (backupConnectionInfo_) {
    backupConnectionInfo_->cancel = true;
  }
}

void ConnectCommand::setControlChain(
    const std::shared_ptr<ControlChain<ConnectCommand*>>& chain)
{
  chain_ = chain;
}

void ConnectCommand::setBackupConnectInfo(
    const std::shared_ptr<BackupConnectInfo>& info)
{
  backupConnectionInfo_ = info;
}

const std::shared_ptr<Request>& ConnectCommand::getProxyRequest() const
{
  return proxyRequest_;
}

bool ConnectCommand::executeInternal()
{
  if (backupConnectionInfo_ && !backupConnectionInfo_->ipaddr.empty()) {
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - Use backup connection address %s",
                    getCuid(), backupConnectionInfo_->ipaddr.c_str()));
    getDownloadEngine()->markBadIPAddress(getRequest()->getConnectedHostname(),
                                          getRequest()->getConnectedAddr(),
                                          getRequest()->getConnectedPort());

    getRequest()->setConnectedAddrInfo(getRequest()->getConnectedHostname(),
                                       backupConnectionInfo_->ipaddr,
                                       getRequest()->getConnectedPort());
    swapSocket(backupConnectionInfo_->socket);
    backupConnectionInfo_.reset();
  }
  if (!checkIfConnectionEstablished(
          getSocket(), getRequest()->getConnectedHostname(),
          getRequest()->getConnectedAddr(), getRequest()->getConnectedPort())) {
    return true;
  }
  if (proxyRequest_ && proxyRequest_->getProtocol() == "socks5" &&
      !processSocks5()) {
    return false;
  }
  if (backupConnectionInfo_) {
    backupConnectionInfo_->cancel = true;
    backupConnectionInfo_.reset();
  }
  chain_->run(this, getDownloadEngine());
  return true;
}

bool ConnectCommand::processSocks5()
{
  if (socks5State_ == 0) {
    if (!proxyRequest_->getUsername().empty() || proxyRequest_->hasPassword()) {
      throw DL_ABORT_EX(
          "SOCKS5 username/password authentication is not supported");
    }
    const auto& host = getRequest()->getHost();
    if (host.empty() || host.size() > 255) {
      throw DL_ABORT_EX("SOCKS5 destination hostname is too long");
    }
    const auto port = getRequest()->getPort();
    socks5Send_.assign("\x05\x01\x00", 3);
    socks5SendOffset_ = 0;
    socks5Recv_.clear();
    socks5RecvExpected_ = 2;
    socks5State_ = 1;
    socks5ConnectRequest_.assign("\x05\x01\x00", 3);
    std::array<char, 16> address;
    if (getRequest()->isIPv6LiteralAddress() &&
        inetPton(AF_INET6, host.c_str(), address.data()) == 0) {
      socks5ConnectRequest_.push_back('\x04');
      socks5ConnectRequest_.append(address.data(), 16);
    }
    else if (inetPton(AF_INET, host.c_str(), address.data()) == 0) {
      socks5ConnectRequest_.push_back('\x01');
      socks5ConnectRequest_.append(address.data(), 4);
    }
    else {
      socks5ConnectRequest_.push_back('\x03');
      socks5ConnectRequest_.push_back(static_cast<char>(host.size()));
      socks5ConnectRequest_ += host;
    }
    socks5ConnectRequest_.push_back(static_cast<char>(port >> 8));
    socks5ConnectRequest_.push_back(static_cast<char>(port & 0xff));
  }

  while (socks5State_ == 1 || socks5State_ == 3) {
    const auto& data = socks5State_ == 1 ? socks5Send_ : socks5ConnectRequest_;
    auto len = data.size() - socks5SendOffset_;
    auto n = getSocket()->writeData(data.data() + socks5SendOffset_, len);
    socks5SendOffset_ += n;
    if (socks5SendOffset_ != data.size()) {
      setWriteCheckSocket(getSocket());
      disableReadCheckSocket();
      addCommandSelf();
      return false;
    }
    socks5State_ = socks5State_ == 1 ? 2 : 4;
    socks5SendOffset_ = 0;
    socks5Recv_.clear();
    socks5RecvExpected_ = socks5State_ == 2 ? 2 : 4;
  }

  if (socks5State_ == 2 || socks5State_ == 4) {
    std::array<char, 256> buf;
    auto len = std::min(buf.size(), socks5RecvExpected_ - socks5Recv_.size());
    getSocket()->readData(buf.data(), len);
    socks5Recv_.append(buf.data(), len);
    if (socks5Recv_.size() < socks5RecvExpected_) {
      if (!getSocket()->wantRead() && !getSocket()->wantWrite()) {
        throw DL_RETRY_EX("SOCKS5 proxy closed the connection");
      }
      setReadCheckSocket(getSocket());
      setWriteCheckSocketIf(getSocket(), getSocket()->wantWrite());
      addCommandSelf();
      return false;
    }
    if (socks5State_ == 2) {
      if (socks5Recv_[0] != 5 || socks5Recv_[1] != 0) {
        throw DL_RETRY_EX("SOCKS5 proxy does not allow no-authentication");
      }
      socks5Send_ = socks5ConnectRequest_;
      socks5State_ = 3;
      return processSocks5();
    }
    if (socks5Recv_.size() == 4) {
      if (socks5Recv_[0] != 5 || socks5Recv_[1] != 0) {
        throw DL_RETRY_EX("SOCKS5 proxy connection request failed");
      }
      switch (static_cast<unsigned char>(socks5Recv_[3])) {
      case 1:
        socks5RecvExpected_ = 10;
        break;
      case 4:
        socks5RecvExpected_ = 22;
        break;
      case 3:
        socks5RecvExpected_ = 5;
        break;
      default:
        throw DL_RETRY_EX("SOCKS5 proxy returned an invalid address");
      }
      return processSocks5();
    }
    if (socks5Recv_.size() == 5 && socks5RecvExpected_ == 5) {
      socks5RecvExpected_ = 7 + static_cast<unsigned char>(socks5Recv_[4]);
      return processSocks5();
    }
    socks5State_ = 5;
  }
  if (socks5State_ == 5) {
    disableReadCheckSocket();
    setWriteCheckSocket(getSocket());
    return true;
  }
  return false;
}

bool ConnectCommand::noCheck() const
{
  return backupConnectionInfo_ && !backupConnectionInfo_->ipaddr.empty();
}

} // namespace aria2
