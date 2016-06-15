/*
 *  vdr-plugin-dvbapi - softcam dvbapi plugin for VDR
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "DeCSA.h"
#include "Log.h"
#include "cscrypt/des.h"

DeCSA *decsa = NULL;

bool CheckNull(const unsigned char *data, int len)
{
  while (--len >= 0)
    if (data[len])
      return false;
  return true;
}

class cMutexLockTmp
{
private:
  cMutexLock *pmutexLock;
  cMutex *pmutex;
public:
  cMutexLockTmp(cMutex *Mutex = NULL, bool block = true)
  {
    pmutexLock = NULL;
    pmutex = Mutex;
    if (block)
      pmutexLock = new cMutexLock(pmutex);
  };
  ~cMutexLockTmp()
  {
    if (pmutexLock)
      delete pmutexLock;
    pmutexLock = NULL;
    pmutex = NULL;
  }

  void UnLock()
  {
    if (pmutexLock != NULL)
      delete pmutexLock;
    pmutexLock = NULL;
  }

  void ReLock()
  {
    if (pmutexLock == NULL)
      pmutexLock = new cMutexLock(pmutex);
  }
};

DeCSAKey::DeCSAKey()
{
  index = -1;
  key = NULL;
  lastcwlog = 0;

  cwSeen = 0;
}

DeCSAKey::~DeCSAKey()
{
  if (key)
  {
    cMutexLock lock(&mutexKEY);
    free_key_struct(key);
  }
  key = NULL;
}

bool DeCSAKey::SetFastEMMCaidSid(int caid, int sid)
{
  cMutexLock lock(&mutexKEY);
  if (key)
  {
    setFastEMMCaidSid(key, caid, sid);
    return true;
  }
  return false;
}

int DeCSAKey::Set_FastEMM_CW_Parity(int pid, int parity, bool bforce, int &oldparity, bool &bfirsttimecheck, bool &bnextparityset, bool &bactivparitypatched)
{
  cMutexLock lock(&mutexKEY);
  if (key)
    return set_FastEMM_CW_Parity(key, pid, parity, bforce, oldparity, bfirsttimecheck, bnextparityset, bactivparitypatched);
  return 1;
}

void DeCSAKey::SetAlgo(uint32_t usedAlgo)
{
  cMutexLock lock(&mutexKEY);
  algo = usedAlgo;
}

uint32_t DeCSAKey::GetAlgo()
{
  cMutexLock lock(&mutexKEY);
  return algo;
}

void DeCSAKey::SetFastEMMPid(int pid)
{
  cMutexLock lock(&mutexKEY);
  if (key)
    setFastEMMPid(key, pid);
}

bool DeCSAKey::GetorCreateKeyStruct()
{
  cMutexLock lock(&mutexKEY);
  if (!key)
  {
    DEBUGLOG("GetorCreateKeyStruct - Init_Parity  idx:%d", index);
    key = get_key_struct();
  }
  return key != 0;
}

bool DeCSAKey::CWExpired()
{
  cMutexLock lock(&mutexKEY);
  if (CheckExpiredCW)
  {
    time_t tnow = time(NULL);
    if (CheckExpiredCW && cwSeen > 0 && (tnow - cwSeen) > MAX_KEY_WAIT)
    {
      if ((tnow - lastcwlog) > 10)      //log max every 10 seconds
      {
        lastcwlog = tnow;
        DEBUGLOG("%s: CheckExpiredCW key is expired", __FUNCTION__);
      }
      return true;
    }
    else
      lastcwlog = tnow;
  }
  return false;
}

void DeCSAKey::Get_FastEMM_CAID(int *caid)
{
  cMutexLock lock(&mutexKEY);
  *caid = 0;
  if (key)
    get_FastEMM_CAID(key, caid);
}

void DeCSAKey::Get_FastEMM_SID(int *caSid)
{
  cMutexLock lock(&mutexKEY);
  *caSid = 0;
  if (key)
    get_FastEMM_SID(key, caSid);
}

void DeCSAKey::Get_FastEMM_PID(int *caPid)
{
  cMutexLock lock(&mutexKEY);
  *caPid = 0;
  if (key)
    get_FastEMM_PID(key, caPid);
}

bool DeCSAKey::Get_FastEMM_struct(FAST_EMM & femm)
{
  cMutexLock lock(&mutexKEY);
  if (key)
  {
    FAST_EMM *fe = get_FastEMM_struct(key);
    femm = *fe;
    return true;
  }
  return false;
}

bool DeCSAKey::GetActiveParity(int pid, int &aparity, int &aparity2)
{
  cMutexLock lock(&mutexKEY);
  if (key)
  {
    getActiveParity(key, pid, aparity, aparity2);
    return true;
  }
  return false;
}

void DeCSAKey::InitFastEmmOnCaid(int Caid)
{
  cMutexLock lock(&mutexKEY);
  if (key)
  {
    struct FAST_EMM *sf = get_FastEMM_struct(key);
    if (sf && Caid == sf->csaCaid)
    {
      sf->oddparityTime = 0;
      sf->evenparityTime = 0;
      sf->nextparity = 0;

      sf->pidAddTime.clear();
      sf->activparity.clear();
      sf->activparity2.clear();
    }
  }
}

void DeCSAKey::SetActiveParity2(int pid, int parity2)
{
  cMutexLock lock(&mutexKEY);
  if (key)
  {
    FAST_EMM *fe = get_FastEMM_struct(key);
    fe->activparity2[pid] = parity2;
  }
}

int DeCSAKey::Decrypt_packets(unsigned char **cluster)
{
  cMutexLock lock(&mutexKEY);
  if (key)
    return decrypt_packets(key, cluster);
  else
    DEBUGLOG("%s: ind:%d Decrypt_packets key is null", __FUNCTION__, index);
  return 0;
}

bool DeCSAKey::Get_control_words(unsigned char *even, unsigned char *odd)
{
  cMutexLock lock(&mutexKEY);
  if (key)
  {
    get_control_words(key, even, odd);
    return true;
  }
  return false;
}

void DeCSAKey::Des(uint8_t * data, unsigned char parity)
{
  cMutexLock lock(&mutexKEY);
  des(data, des_key_schedule[parity], 0);
}

void DeCSAKey::Des_set_key(const unsigned char *cw, unsigned char parity)
{
  cMutexLock lock(&mutexKEY);
  cwSeen = time(NULL);
  des_set_key(cw, des_key_schedule[parity]);
}

bool DeCSAKey::Set_even_control_word(const unsigned char *even)
{
  cMutexLock lock(&mutexKEY);
  if (key)
  {
    set_even_control_word(key, even);
    return true;
  }
  return false;
}

bool DeCSAKey::Set_odd_control_word(const unsigned char *odd)
{
  cMutexLock lock(&mutexKEY);
  if (key)
  {
    set_odd_control_word(key, odd);
    return true;
  }
  return false;
}

void DeCSAKey::Init_Parity2(bool binitcsa)
{
  cMutexLock lock(&mutexKEY);
  if (key)
  {
    if (binitcsa)
      DEBUGLOG("Init_Parity idx:%d", index);
    else
      DEBUGLOG("Init_Parity from Timeout idx:%d", index);

    Init_FastEMM(key, binitcsa);
  }
}

DeCSAAdapter::DeCSAAdapter()
{
  cardindex = -1;

  bCW_Waiting = false;
  bAbort = false;

  csnew = get_suggested_cluster_size();
  //DEBUGLOG("clustersize=%d rangesize=%d", csnew, csnew * 2 + 5);
  rangenew = MALLOC(unsigned char *, (csnew * 2 + 5));
}

DeCSAAdapter::~DeCSAAdapter()
{
  free(rangenew);
}

void DeCSAAdapter::CancelWait()
{
  if (bCW_Waiting)
  {
    DEBUGLOG("%s: decsa CW Waiting", __FUNCTION__);
    bAbort = true;
    cMutexLock lock(&mutexStopDecrypt);
    bAbort = false;
    DEBUGLOG("%s: decsa CW Waiting Aborted", __FUNCTION__);
  }
}

void DeCSAAdapter::Init_Parity(DeCSAKey * keys, int sid, int slot)
{
  cMutexLock lock(&mutexAdapter);

  if (sid < 0 && slot < 0)
    return;
  if (sid >= 0)
    DEBUGLOG("Init_Parity cardindex:%d SID %d (0x%04X)", cardindex, sid, sid);
  else
    DEBUGLOG("Init_Parity cardindex:%d Slot %d", cardindex, slot);

  map < int, unsigned char >::iterator it;
  for (it = AdapterPidMap.begin(); it != AdapterPidMap.end(); ++it)
  {
    int ipid = it->first;
    int iidx = it->second;

    int caCaid = -1;
    int caSid = -1;
    int caPid = -1;

    keys[iidx].Get_FastEMM_CAID(&caCaid);
    keys[iidx].Get_FastEMM_SID(&caSid);
    keys[iidx].Get_FastEMM_PID(&caPid);

    {
      if (sid >= 0 && caSid == sid)
      {
        keys[iidx].Init_Parity2();
      }
      else if (slot >= 0 && slot == iidx)
      {
        keys[iidx].Init_Parity2();

        DEBUGLOG("Init_Parity delete pidmap  cardindex:%d idx:%d", cardindex, iidx);

        AdapterPidMap.erase(ipid);
      }
    }
  }
}

int DeCSAAdapter::SearchPIDinMAP(int pid)
{
  cMutexLock lock(&mutexAdapter);
  //we must search for pid, otherwise on tune start we use always idx 0
  map<int, unsigned char>::iterator it;
  for (it = AdapterPidMap.begin(); it != AdapterPidMap.end(); ++it)
  {
    if (it->first == pid)
      return it->second;
  }
  //DEBUGLOG("%s: pid not found in pidmap cardindex:%d pid:%d(0x%04X) l:%d len:%d", __FUNCTION__, adapter_index, pid, pid, l, len);
  return -1;
}

void DeCSAAdapter::SetCaPid(int pid, int index)
{
  cMutexLock lock(&mutexAdapter);
  AdapterPidMap[pid] = index == -1 ? 0 : index;
}

void DeCSAAdapter::SetDVBAPIPid(DeCSA * parent, int slot, int dvbapiPID)
{
  if (dvbapiPID >= 0 && slot >= 0 && slot < MAX_CSA_IDX)
  {
    cMutexLock lock(&mutexAdapter);
    int idxOK = -1;
    map < int, unsigned char >::iterator it;
    for (it = AdapterPidMap.begin(); it != AdapterPidMap.end(); ++it)
    {
      //int ipid = it->first;
      int iidx = it->second;
      if (iidx == slot)
      {
        idxOK = iidx;
        break;
      }
    }
    if (idxOK < 0)
      idxOK = slot;

    parent->SetFastEMMPid(cardindex, idxOK, slot, dvbapiPID);
  }
}

DeCSA::DeCSA()
{
  for (int i = 0; i < MAXADAPTER; i++)
    DeCSAArray[i].cardindex = i;

  for (int i = 0; i < MAX_CSA_IDX; i++)
    DeCSAKeyArray[i].index = i;

  ResetState();
}

DeCSA::~DeCSA()
{
  DEBUGLOG("%s", __FUNCTION__);
  for (int i = 0; i < MAX_CSA_IDX; i++)
  {
  }
}

void DeCSA::ResetState(void)
{
  DEBUGLOG("%s", __FUNCTION__);
}

void DeCSA::InitFastEmmOnCaid(int Caid)
{
  //initialize disable check (wait for odd, even and so on..)
  //should disable CW check for about 14 seconds- 2 CW times
  for (int i = 0; i < MAX_CSA_IDX; i++)
    DeCSAKeyArray[i].InitFastEmmOnCaid(Caid);
}

bool DeCSA::SetDescr(ca_descr_t *ca_descr, bool initial, int adapter_index)
{
  DEBUGLOG("%s addapter:%d", __FUNCTION__, adapter_index);

  cMutexLock lock(&mutexDeCSANew);

  int idx = ca_descr->index;
  if (idx < MAX_CSA_IDX && GetorCreateKeyStruct(idx))
  {
    FAST_EMM femm;
    DeCSAKeyArray[idx].Get_FastEMM_struct(femm);

    uint64_t now = GetTick();
    uint64_t evendelta = -1;
    if (femm.evenparityTime > 0)
      evendelta = now - femm.evenparityTime;
    uint64_t odddelta = -1;
    if (femm.oddparityTime > 0)
      odddelta = now - femm.oddparityTime;

    unsigned char cweven[8];
    unsigned char cwodd[8];
    DeCSAKeyArray[idx].Get_control_words(cweven, cwodd);

    DEBUGLOG("idx:%d adapter:%d EVENKEYOLD: CW: %02x %02x %02x %02x %02x %02x %02x %02x deltams:%lld nextparity:%d csaSid:%04x csaCaid:%04x csaPid:%04x", idx, adapter_index, cweven[0], cweven[1], cweven[2], cweven[3], cweven[4], cweven[5], cweven[6], cweven[7], (lldcast) evendelta, femm.nextparity, femm.csaSid, femm.csaCaid, femm.csaPid);
    DEBUGLOG("idx:%d adapter:%d  ODDKEYOLD: CW: %02x %02x %02x %02x %02x %02x %02x %02x deltams:%lld nextparity:%d csaSid:%04x csaCaid:%04x csaPid:%04x", idx, adapter_index, cwodd[0], cwodd[1], cwodd[2], cwodd[3], cwodd[4], cwodd[5], cwodd[6], cwodd[7], (lldcast) odddelta, femm.nextparity, femm.csaSid, femm.csaCaid, femm.csaPid);

    DEBUGLOG("idx:%d adapter:%d  %4s CW key set index:%d CW: %02x %02x %02x %02x %02x %02x %02x %02x initial:%d", idx, adapter_index, ca_descr->parity ? "odd" : "even", ca_descr->index, ca_descr->cw[0], ca_descr->cw[1], ca_descr->cw[2], ca_descr->cw[3], ca_descr->cw[4], ca_descr->cw[5], ca_descr->cw[6], ca_descr->cw[7], initial);


    DeCSAKeyArray[idx].Des_set_key(ca_descr->cw, ca_descr->parity);

    if (ca_descr->parity == 0)
      DeCSAKeyArray[idx].Set_even_control_word(ca_descr->cw);
    else
      DeCSAKeyArray[idx].Set_odd_control_word(ca_descr->cw);
  }
  return true;
}

void DeCSA::DebugLogPidmap()
{
  if (LogLevel < 3)
    return;
  for (int iadapter = 0; iadapter < MAXADAPTER; iadapter++)
  {
    if (DeCSAArray[iadapter].AdapterPidMap.size() > 0)
    {
      map < int, unsigned char >::iterator it;
      for (it = DeCSAArray[iadapter].AdapterPidMap.begin(); it != DeCSAArray[iadapter].AdapterPidMap.end(); ++it)
      {
        int ipid = it->first;
        int iidx = it->second;
        FAST_EMM femm;
        if (DeCSAKeyArray[iidx].Get_FastEMM_struct(femm))
        {
          uint64_t now = GetTick();
          uint64_t evendelta = -1;
          if (femm.evenparityTime > 0)
            evendelta = now - femm.evenparityTime;
          uint64_t odddelta = -1;
          if (femm.oddparityTime > 0)
            odddelta = now - femm.oddparityTime;

          int aparity = 0;
          int aparity2 = 0;
          DeCSAKeyArray[iidx].GetActiveParity(ipid, aparity, aparity2);

          DEBUGLOG("DebugLogPidmap cardindex:%d pid:%d(0x%04X) idx:%d SID:%d(0x%04X) caid:%d(0x%04X) DvbApiPid:%d(0x%04X) activparity:%d activparity2:%d nextparity:%d evendelta:%lld odddelta:%lld", iadapter, ipid, ipid, iidx, femm.csaSid, femm.csaSid, femm.csaCaid, femm.csaCaid, femm.csaPid, femm.csaPid, aparity, aparity2, femm.nextparity, (lldcast) evendelta, (lldcast) odddelta);
        }
      }
    }
  }
}

void DeCSA::Init_Parity(int cardindex, int sid, int slot)
{
  if (cardindex < 0)
    return;
  if (sid < 0 && slot < 0)
    return;
  DeCSAArray[cardindex].Init_Parity(DeCSAKeyArray, sid, slot);
}


void DeCSA::SetDVBAPIPid(int adapter, int slot, int dvbapiPID)
{
  if (adapter >= 0 && dvbapiPID >= 0 && slot >= 0 && slot < MAX_CSA_IDX)
    DeCSAArray[adapter].SetDVBAPIPid(this, slot, dvbapiPID);
}

void DeCSA::SetFastEMMPid(int cardindex, int idx, int slot, int dvbapiPID)
{
  if (idx >= 0 && GetorCreateKeyStruct(idx))
  {
    DEBUGLOG("SetDVBAPIPid %d.%d (PID %d (0x%04X))  idx:%d", cardindex, slot, dvbapiPID, dvbapiPID, idx);
    //Init_FastEMM(keys[idxOK]);
    DeCSAKeyArray[idx].SetFastEMMPid(dvbapiPID);
  }
}

bool DeCSA::GetorCreateKeyStruct(int idx)
{
  if (idx >= 0)
    return DeCSAKeyArray[idx].GetorCreateKeyStruct();
  return false;
}

bool DeCSA::SetCaPid(uint8_t adapter_index, ca_pid_t *ca_pid)
{
  DEBUGLOG("%s: adapter_index=%d, pid=0x%04x, index=0x%x", __FUNCTION__, adapter_index, ca_pid->pid, ca_pid->index);
  cMutexLock lock(&mutexDeCSANew);
  if (ca_pid->index < MAX_CSA_IDX && ca_pid->pid < MAX_CSA_PID)
  {
    if (ca_pid->index >= 0 && adapter_index >= 0 && adapter_index < MAXADAPTER)
      DeCSAArray[adapter_index].SetCaPid(ca_pid->pid, ca_pid->index);
    DEBUGLOG("%d.%d: set pid 0x%04x", adapter_index, ca_pid->index, ca_pid->pid);
  }
  else
    ERRORLOG("%s: Parameter(s) out of range: adapter_index=%d, pid=0x%04x, index=0x%x", __FUNCTION__, adapter_index, ca_pid->pid, ca_pid->index);
  return true;
}

void DeCSA::CancelWait()
{
  for (int i = 0; i < MAXADAPTER; i++)
    DeCSAArray[i].CancelWait();
}

void DeCSA::SetAlgo(uint32_t index, uint32_t usedAlgo)
{
  if (index >= 0 && index < MAX_CSA_IDX)
    DeCSAKeyArray[index].SetAlgo(usedAlgo);
}

uint32_t DeCSA::GetAlgo(int idx)
{
  if (idx < 0 || idx >= MAX_CSA_IDX)
    return -1;
  return DeCSAKeyArray[idx].GetAlgo();
}

unsigned char ts_packet_get_payload_offset(unsigned char *ts_packet)
{
  if (ts_packet[0] != TS_SYNC_BYTE)
    return 0;

  unsigned char adapt_field   = (ts_packet[3] &~ 0xDF) >> 5; // 11x11111
  unsigned char payload_field = (ts_packet[3] &~ 0xEF) >> 4; // 111x1111

  if (!adapt_field && !payload_field)     // Not allowed
    return 0;

  if (adapt_field)
  {
    unsigned char adapt_len = ts_packet[4];
    if (payload_field && adapt_len > 182) // Validity checks
      return 0;
    if (!payload_field && adapt_len > 183)
      return 0;
    if (adapt_len + 4 > TS_SIZE)  // adaptation field takes the whole packet
      return 0;
    return 4 + 1 + adapt_len;     // ts header + adapt_field_len_byte + adapt_field_len
  }
  else
  {
    return 4; // No adaptation, data starts directly after TS header
  }
}

int DeCSA::SearchPIDinMAP(int adapter_index, int pid)
{
  if (adapter_index >= 0 && adapter_index < MAXADAPTER && pid >= 0)
    return DeCSAArray[adapter_index].SearchPIDinMAP(pid);
  return -1;
}

//The encrypted control word is broadcast in an ECM approximately once every two seconds
//The Control Word used to encrypt the transport stream packets are changed regularly,
//usually every 10 seconds.If the Control Words change stops for whatever reason the STBs can use the same Control Word
//to decrypt the incoming signal until the problem is fixed.This is a serious security issue.

//In each PID header there are 2 bits telling the decoder if the Odd or Even Control Word should be used.The ECM
//normally contains two Control Words.This mechanism allows the ECM to carry both the Control Word currently used
//and the Control Word which will be used for scrambling the next time the Control Word changes.This ensures that the
//STB always has the Control Word needed to descramble the content.

//Sky Germany only has one Control Word.
//We can see the CW around 620ms before it shoul be used.

bool DeCSA::Decrypt(uint8_t adapter_index, unsigned char *data, int len, bool force)
{
  uint64_t sleeptime = 0;
  if (adapter_index < 0 || adapter_index >= MAXADAPTER)
    return false;
  return DeCSAArray[adapter_index].Decrypt(this, data, len, force, sleeptime);
}

bool DeCSAAdapter::Decrypt(DeCSA *parent, unsigned char *data, int len, bool force, uint64_t &sleeptime)
{
  bool bEnableFastECMCheck = true;

  uint8_t adapter_index = cardindex;
  cTimeMs starttime(cTimeMs::Now());

  cMutexLockTmp lockDecrypt(&mutexDecrypt);     //bringt nichts wird sowieso nur von einem adapter thread aufgerufen

  cMutexLockTmp lockPIDMAPnew(&mutexAdapter);

  sleeptime = 0;

  int itimeout = 4000;
  int iSleep = 50;
  int imaxSleep = itimeout / iSleep;
  cTimeMs TimerTimeout(itimeout);       //TS_SCRAMBLING_TIMEOUT  new cTSBuffer(fd_dvr, MEGABYTE(16)

  if (!rangenew)
  {
    ERRORLOG("%s: Error allocating memory for DeCSA", __FUNCTION__);
    return false;
  }

  int offset;
  int r = -2, ccs = 0, currIdx = -1;
  bool newRange = true;
  rangenew[0] = 0;

  len -= (TS_SIZE - 1);
  int l;

  int wantsparity = 0;
  int curPid = 0;

  for (l = 0; l < len; l += TS_SIZE)
  {
    if (data[l] != TS_SYNC_BYTE)
    {                           // let higher level cope with that
      break;
    }
    unsigned int ev_od = data[l + 3] & 0xC0;
    /*
       we could have the following values:
       '00' = Not scrambled
       '01' (0x40) = Reserved for future use
       '10' (0x80) = Scrambled with even key
       '11' (0xC0) = Scrambled with odd key
    */
    if (ev_od & 0x80)
    {                           // encrypted
      offset = ts_packet_get_payload_offset(data + l);
      int pid = ((data[l + 1] << 8) + data[l + 2]) & MAX_CSA_PID;
      int idx = SearchPIDinMAP(pid);
      if (idx >= 0 && (pid < MAX_CSA_PID) && (currIdx < 0 || idx == currIdx))
      {                         // same or no index
        currIdx = idx;
        curPid = pid;

        if (ev_od == 0x80)      //even
          wantsparity = 1;
        else if (ev_od == 0xC0) //odd
          wantsparity = 2;

        if (currIdx < 0 || (currIdx + 1) >= MAX_CSA_IDX)
          ERRORLOG("%s: CheckExpiredCW currIdx is out of range %d", __FUNCTION__, currIdx);

        // return if the key is expired
        if (parent->DeCSAKeyArray[currIdx].CWExpired())
          return false;

        if (parent->GetAlgo(currIdx) == CA_ALGO_DES)
        {
          if ((ev_od & 0x40) == 0)
          {
            for (int j = offset; j + 7 < 188; j += 8)
              parent->DeCSAKeyArray[currIdx].Des(&data[l + j], 0);

          }
          else
          {
            for (int j = offset; j + 7 < 188; j += 8)
              parent->DeCSAKeyArray[currIdx].Des(&data[l + j], 1);

          }
          data[l + 3] &= 0x3f;    // consider it decrypted now
        }
        else
        {
          if (newRange)
          {
            r += 2;
            newRange = false;
            rangenew[r] = &data[l];
            rangenew[r + 2] = 0;
          }
          rangenew[r + 1] = &data[l + TS_SIZE];

          if (++ccs >= csnew)
            break;
        }
      }
      else
        newRange = true;        // other index, create hole
    }
    else
    {                           // unencrypted
      // nothing, we don't create holes for unencrypted packets
    }
  }

  if (currIdx >= 0 && parent->GetAlgo(currIdx) == CA_ALGO_DES)
    return true;
  if (r >= 0)
  {                             // we have some range
    if (ccs >= csnew || force)
    {
      if (currIdx >= 0 && parent->GetorCreateKeyStruct(currIdx))
      {
        if (wantsparity > 0)
        {
          bool bFastECM = false;
          int caCaid = -1;
          int caSid = -1;
          int caPid = -1;
          if (capmt && bEnableFastECMCheck)
          {
            bool bdebuglogoCAID = false;
            parent->DeCSAKeyArray[currIdx].Get_FastEMM_CAID(&caCaid);
            parent->DeCSAKeyArray[currIdx].Get_FastEMM_SID(&caSid);
            parent->DeCSAKeyArray[currIdx].Get_FastEMM_PID(&caPid);
            if (caCaid <= 0)
            {
              if (caPid >= 0)
              {
                uint16_t caidneu = 0;//capmt->GetCAIDFromPid(adapter_index, caPid, caSid);
                if (caidneu > 0)
                {
                  DEBUGLOG("%s: SetFastEMMCaidSid adapter:%d CAID: %04X SID: %04X parity:%d pid:%d idx:%d", __FUNCTION__, adapter_index, caidneu, caSid, wantsparity, curPid, currIdx);
                  parent->DeCSAKeyArray[currIdx].SetFastEMMCaidSid(caidneu, caSid);
                  caCaid = caidneu;
                  bdebuglogoCAID = true;
                }
              }
            }

            if (caCaid == 0x09C4 || caCaid == 0x098C ||  //SKY DE
                caCaid == 0x09CD ||     //Sky IT
                caCaid == 0x0963)       //Sky UK
            {
              if (bdebuglogoCAID)
              {
                DEBUGLOG("%s: using Fast ECM adapter:%d CAID: %04X SID: %04X parity:%d pid:%d idx:%d", __FUNCTION__, adapter_index, caCaid, caSid, wantsparity, curPid, currIdx);
                parent->DebugLogPidmap();
              }
              bFastECM = true;
            }
            else                //if (caCaid!=0x00)
            {
              if (bdebuglogoCAID)
              {
                DEBUGLOG("%s: not using Fast ECM adapter:%d CAID: %04X SID: %04X parity:%d pid:%d idx:%d", __FUNCTION__, adapter_index, caCaid, caSid, wantsparity, curPid, currIdx);
                parent->DebugLogPidmap();
              }
            }
          }

          if (bFastECM)
          {
            bool bfirsttimecheck;
            bool bnextparityset;
            bool bactivparitypatched;

            int oldparity = 0;
            int iok = parent->DeCSAKeyArray[currIdx].Set_FastEMM_CW_Parity(curPid, wantsparity, false, oldparity, bfirsttimecheck, bnextparityset, bactivparitypatched);

            if (bfirsttimecheck)
              DEBUGLOG("bfirsttimecheck pid:%d idx:%d adapter:%d", curPid, currIdx, adapter_index);
            if (bnextparityset)
              DEBUGLOG("bnextparityset pid:%d idx:%d adapter:%d", curPid, currIdx, adapter_index);
            if (bactivparitypatched)
              DEBUGLOG("bactivparitypatched pid:%d idx:%d adapter:%d", curPid, currIdx, adapter_index);
            if (oldparity != wantsparity)
            {
              DEBUGLOG("need new CW Parity - changed from old:%d new:%d pid:%d idx:%d adapter:%d", oldparity, wantsparity, curPid, currIdx, adapter_index);
            }
            if (iok == 0 && bFastECM)
            {
              bCW_Waiting = true;
              cMutexLock lockstop(&mutexStopDecrypt);
                ERRORLOG("%s: set_FastEMM_CW_Parity MUST WAIT parity:%d pid:%d idx:%d adapter:%d len:%d", __FUNCTION__, wantsparity, curPid, currIdx, adapter_index, len);
              parent->DebugLogPidmap();

              int isleepcount = 0;
              do
              {
                isleepcount++;
                lockPIDMAPnew.UnLock();
                cCondWait::SleepMs(iSleep);
                lockPIDMAPnew.ReLock(); //eventuell hier problem?

                if (bAbort)
                {
                  bCW_Waiting = false;
                  bAbort = false;
                  ERRORLOG("%s: bAbort parity wait adapter:%d", __FUNCTION__, adapter_index);
                  return false;
                }

                iok = parent->DeCSAKeyArray[currIdx].Set_FastEMM_CW_Parity(curPid, wantsparity, false, oldparity, bfirsttimecheck, bnextparityset, bactivparitypatched);
                if (bfirsttimecheck)
                  DEBUGLOG("bfirsttimecheck pid:%d idx:%d adapter:%d", curPid, currIdx, adapter_index);
                if (bnextparityset)
                  DEBUGLOG("bnextparityset pid:%d idx:%d adapter:%d", curPid, currIdx, adapter_index);
                if (bactivparitypatched)
                  DEBUGLOG("bactivparitypatched pid:%d idx:%d adapter:%d", curPid, currIdx, adapter_index);
                if (iok == 1)
                {
                  sleeptime = starttime.Elapsed/*2*/();
                  ERRORLOG("%s: set_FastEMM_CW_Parity MUST WAIT SUCCESS parity:%d pid:%d idx:%d adapter:%d len:%d time:%lld", __FUNCTION__, wantsparity, curPid, currIdx, adapter_index, len, (lldcast) sleeptime);
                }
                else
                {
                  if (TimerTimeout.TimedOut() || isleepcount > imaxSleep)
                  {
                    parent->DeCSAKeyArray[currIdx].Set_FastEMM_CW_Parity(curPid, wantsparity, true, oldparity, bfirsttimecheck, bnextparityset, bactivparitypatched);   //otherwise we sleep every time.
                    parent->DeCSAKeyArray[currIdx].Init_Parity2(false);
                    sleeptime = starttime.Elapsed/*2*/();
                    ERRORLOG("%s: set_FastEMM_CW_Parity MUST WAIT TIMEOUT parity:%d pid:%d idx:%d adapter:%d len:%d time:%lld", __FUNCTION__, wantsparity, curPid, currIdx, adapter_index, len, (lldcast) sleeptime);
                    iok = 1;
                  }
                }
              } while (iok == 0);

              bCW_Waiting = false;
              sleeptime = starttime.Elapsed/*2*/();
            }
          }
          else                  //only log changed...
          {
            FAST_EMM femm;
            if (parent->DeCSAKeyArray[currIdx].Get_FastEMM_struct(femm))
            {
              int aparity2 = femm.activparity2[curPid];
              int oldparity = aparity2;
              parent->DeCSAKeyArray[currIdx].SetActiveParity2(curPid, wantsparity);
              if (oldparity != wantsparity)
                DEBUGLOG("need new CW Parity - changed from old:%d new:%d pid:%d idx:%d adapter:%d", oldparity, wantsparity, curPid, currIdx, adapter_index);
            }
          }
        }

        unsigned char *pkt = *rangenew;
        if (!pkt)
          DEBUGLOG("%s: RANGE is NULL", __FUNCTION__);

        int n = parent->DeCSAKeyArray[currIdx].Decrypt_packets(rangenew);
        if (n > 0)
          return true;
        else
          DEBUGLOG("%s: decrypt_packets returns <= 0 n:%d adapter:%d parity:%d pid:%d idx:%d len:%d", __FUNCTION__, n, adapter_index, wantsparity, curPid, currIdx, len);
      }
    }
  }
  return false;
}

void DeCSA::StopDecrypt(int adapter_index)
{
  if (adapter_index < 0 || adapter_index >= MAXADAPTER)
    return;

  if (DeCSAArray[adapter_index].bCW_Waiting)
  {
    DEBUGLOG("decsa CW Waiting %s", __FUNCTION__);
    DeCSAArray[adapter_index].bAbort = true;
    cMutexLock lock(&DeCSAArray[adapter_index].mutexStopDecrypt);
    DeCSAArray[adapter_index].bAbort = false;
    DEBUGLOG("decsa CW Waiting Aborted %s", __FUNCTION__);
  }
}
