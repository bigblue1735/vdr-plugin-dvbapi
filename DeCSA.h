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

#ifndef ___DECSA_H
#define ___DECSA_H

#include <map>
#include <linux/dvb/ca.h>
#include <vdr/dvbdevice.h>
#include <vdr/thread.h>

#ifdef LIBDVBCSA
extern "C" {
#include <dvbcsa/dvbcsa.h>
}
#else
#include "FFdecsa/FFdecsa.h"
#endif

#define MAX_CSA_PID  0x1FFF
#define MAX_CSA_IDX  32
#define MAX_KEY_WAIT 25         // max seconds to consider a CW as valid
#define MAXADAPTER   64
#define lldcast      long long int

#include "DVBAPI.h"

using namespace std;

class DeCSA;

class DeCSAKey                  // helper class for FFdecsa
{
public:
  DeCSAKey();
  ~DeCSAKey();

  void* key;
  time_t cwSeen;                // last time the CW for the related key was seen
  time_t lastcwlog;

  uint32_t algo;
  uint32_t des_key_schedule[2][32];

  int index;

  bool CWExpired(); //return true if expired
  bool GetorCreateKeyStruct();
  void Des(uint8_t* data, unsigned char parity);
  void Des_set_key(const unsigned char *cw, unsigned char parity);
  bool Get_control_words(unsigned char *even, unsigned char *odd);
  bool Set_even_control_word(const unsigned char *even);
  bool Set_odd_control_word(const unsigned char *odd);
  int Decrypt_packets(unsigned char **cluster);

  void SetFastEMMPid(int pid);
  void Get_FastEMM_CAID(int* caid);
  void Get_FastEMM_SID(int* caSid);
  void Get_FastEMM_PID(int* caPid);
  bool Get_FastEMM_struct(FAST_EMM& femm);
  void Init_Parity2(bool binitcsa = true);
  bool SetFastEMMCaidSid(int caid, int sid);
  int Set_FastEMM_CW_Parity(int pid, int parity, bool bforce, int& oldparity, bool& bfirsttimecheck, bool& bnextparityset, bool& bactivparitypatched);
  void SetActiveParity2(int pid,int parity2);
  void InitFastEmmOnCaid(int Caid);
  bool GetActiveParity(int pid, int& aparity, int& aparity2);

  void SetAlgo(uint32_t usedAlgo);
  uint32_t GetAlgo();

  cMutex mutexKEY;
};

class DeCSAAdapter
{
public:
  DeCSAAdapter();
  ~DeCSAAdapter();

  int cardindex;

  map<int, unsigned char> AdapterPidMap;

  void Init_Parity(DeCSAKey *keys, int sid, int slot);
  void SetDVBAPIPid(DeCSA* parent, int slot, int dvbapiPID);
  void SetCaPid(int pid, int index);
  int SearchPIDinMAP(int pid);
  bool Decrypt(DeCSA* parent,unsigned char *data, int len, bool force, uint64_t& sleeptime);
  void CancelWait();

  cMutex mutexAdapter;
  cMutex mutexDecrypt;
  cMutex mutexStopDecrypt;

  int csnew;

  unsigned char **rangenew;

  bool bCW_Waiting;
  bool bAbort;
};

class DeCSA
{
public:
  DeCSAAdapter DeCSAArray[MAXADAPTER]; //maximal 128 adapter
  DeCSAKey DeCSAKeyArray[MAX_CSA_IDX]; //maximal 32 verschlüsselte kanäle über alle adapter

  cMutex mutexDeCSANew;

  void ResetState(void);
  // to prevent copy constructor and assignment
  DeCSA(const DeCSA&);
  DeCSA& operator=(const DeCSA&);
  bool GetorCreateKeyStruct(int idx);

public:
  DeCSA();
  ~DeCSA();
  int SearchPIDinMAP(int adapter_index, int pid);
  bool Decrypt(uint8_t adapter_index, unsigned char *data, int len, bool force);
  bool SetDescr(ca_descr_t *ca_descr, bool initial, int adapter_index);
  bool SetCaPid(uint8_t adapter_index, ca_pid_t *ca_pid);
  void SetAlgo(uint32_t index, uint32_t usedAlgo);
  uint32_t GetAlgo(int idx);
  void CancelWait();
  void SetDVBAPIPid(int adapter, int slot, int dvbapiPID);
  void Init_Parity(int cardindex, int sid, int slot);
  void DebugLogPidmap();
  void InitFastEmmOnCaid(int Caid);
  void SetFastEMMPid(int cardindex, int idx, int slot, int dvbapiPID);
  void StopDecrypt(int adapter_index);
};

extern DeCSA *decsa;

#endif // ___DECSA_H
