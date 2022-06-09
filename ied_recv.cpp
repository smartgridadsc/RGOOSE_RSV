#include <array>
#include <bitset>
#include <chrono>
#include <cmath>
#include <ctime>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <string>
#include <vector>
#include <climits>

// For parsing SED file (in XML format)
#include "parse_sed.hpp"

// For netdevice - low-level access to Linux network devices
#include <sys/ioctl.h>
#include <net/if.h>

// For Networking/Socket and multicast
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "udpSock.hpp"
#include "zz_diagnose.hpp"

// For IED operations/debugging
#include "ied_utils.hpp"

#define IEDUDPPORT 102
#define MAXBUFLEN 1024

// Checks if received data conforms to R-GOOSE/R-SV specifications or not
// And if so, updates GOOSE Data Records as output parameter "cbOut"
bool valid_GSE_SMV(const unsigned char (&buf)[MAXBUFLEN], const int numbytes, GooseSvData &cbOut)
{
    if ( (numbytes > MAXBUFLEN) || (numbytes < 40) )    // Data received should not be greater than assigned buffer length
    {                                                   // Also, sum of length of header/footer >= 40 bytes
        std::cerr << "[!] Error: Buffer length out of range\n";
        return false;
    }

    std::string   sess_prot{};      // To store Control Block's type ("GSE" or "SMV") as decoded from Session Identifier (SI)
    unsigned int  current_spduLen{};
    unsigned int  current_spduNum{};
    unsigned int  current_payloadLen{};
    unsigned long current_appID{};
    size_t        signature_idx{};
    unsigned char signature_len{};

    // Require LI = 0x01 and TI = 0x40
    if ((buf[0] == 0x01) && (buf[1] == 0x40))
    {
        // SI = 0xA1 for R-GOOSE
        if (buf[2] == 0xA1)
        {
            sess_prot = "GSE";
        }
        // SI = 0xA2 for R-SV
        else if (buf[2] == 0xA2)
        {
            sess_prot = "SMV";
        }
        else
        {
            std::cerr << "[!] Error: Session protocol not implemented\n";
            return false;
        }
    }
    else
    {
        std::cerr << "[!] Error: Application profile unknown\n";
        return false;
    }

    if ( (buf[3] != (buf[5] + 2)) || buf[4] != 0x80 )
    {
        std::cerr << "[!] Error in Common Header\n";
        return false;
    }

    if (buf[14] != 0x00 || buf[15] != 0x01)
    {
        std::cerr << "[!] Error: Unexpected Session Protocol Version Number\n";
        return false;        
    }
    
    current_spduNum = (buf[10] << 24) + (buf[11] << 16) 
                        + (buf[12] << 8) + buf[13];
    /* Exclude initialization scenario (previous = 0)
     *   and exclude rollover scenario (previous = UINT_MAX, current = 0).
     * Look for "reused" SPDU Number.
     */
    if (!( (cbOut.prev_spduNum == 0) || (current_spduNum == 0 && cbOut.prev_spduNum == UINT_MAX) )
            && current_spduNum <= cbOut.prev_spduNum)
    {
        /* std::cout << "[Info] Outdated SPDU Number. Data ignored.\n"
         *           << "\tExpected SPDU Number: " << (cbOut.prev_spduNum + 1) << '\n'
         *           << "\tObserved SPDU Number: " << current_spduNum << '\n';
         */
        return false;
    } // No output prints if packet is out-of-order (assumes earlier packet(s) lost)    

    current_spduLen = (buf[6] << 24) + (buf[7] << 16) 
                      + (buf[8] << 8) + buf[9];

    // Security Information skipped in this implementation

    // Payload Length's most significant byte is at index 28
    current_payloadLen = (buf[28] << 24) + (buf[29] << 16) 
                         + (buf[30] << 8) + buf[31];
    signature_idx = 28 + current_payloadLen;

    // Check Signature Block
    if (buf[signature_idx] != 0x85)
    {
        std::cerr << "[!] Error in Signature\n";
        return false;
    }
    /* Check index of last byte using two different computations:
     *      (i) SPDU Length
     *     (ii) Signature Length
     */
    signature_len = buf[signature_idx + 1];
    // Index of least sig byte of SPDU Length = 9
    if ( (9 + current_spduLen) != ((signature_idx + 1) + signature_len) )
    {
        std::cerr << "[!] Error: Inconsistent Lengths detected\n";
        return false;        
    }

    // No verification of HMAC in this implementation

    /* Check Payload */
    // Pay-load type (at index 32)
    if ( !(  (buf[32] == 0x81 && sess_prot == "GSE")
          || (buf[32] == 0x82 && sess_prot == "SMV") ) )
    {
        std::cerr << "[!] Error: Payload Type inconsistent with Session Identifier\n";
        return false;   
    }
    // Tunneled packets and Management APDUs omitted in this implementation

    // Simulation (at index 33)
    if (buf[33] != 0)
    {
        std::cerr << "[!] Error: Incorrect value detected in 'Simulation' field\n";
        return false; 
    }

    // APDU Length's most significant byte is at index 36
    if (signature_idx != (36 + (buf[36] << 8) + buf[37]))
    {
        std::cerr << "[!] Error: APDU Length in Payload\n";
        return false;     
    }

    // APPID (at indexes 34-35)
    current_appID = (buf[34] << 8) + buf[35];
    if (current_appID != std::stoul(cbOut.appID, nullptr, 16))
    {
        std::cerr << "[!] Error: Incorrect appID in Payload\n";
        return false; 
    }

    /* Check PDU
     *  - First byte at index 38
     *  - Last byte at index (signature_idx - 1)
     */
    if (sess_prot == "GSE")
    {
        if (buf[38] != 0x61 || buf[39] != 0x81)
        {
            std::cerr << "[!] Error: GOOSE PDU Tag\n";
            return false;         
        }

        if ((38 + buf[40]) != signature_idx)
        {
            std::cerr << "[!] Error: GOOSE PDU Length\n";
            return false;         
        }

        // For iterating through the various Tag-Length-Value's of the GOOSE PDU
        size_t tag_idx{};
        size_t len_idx{};

        // gocbRef (Tag at index 41 = PDU first byte's index + 3)
        tag_idx = 41;
        len_idx = tag_idx + 1;
        assert(len_idx < signature_idx);    // Ensure still 'digging' in the PDU
        if (buf[tag_idx] != 0x80)
        {
            std::cerr << "[!] Error: goCBRef Tag\n";
            return false;          
        }

        std::string current_gocbRef{};
        for (size_t i = 0; i < buf[len_idx]; i++)
        {
            current_gocbRef += buf[(len_idx + 1) + i];
        }
        if (current_gocbRef != cbOut.cbName)
        {
            std::cerr << "[!] Error: goCBRef mismatch\n";
            return false;          
        }

        // timeAllowedToLive
        tag_idx = (len_idx + 1) + buf[len_idx]; // new tag_idx = (old len_idx + 1 = start of Value field) + old length
        len_idx = tag_idx + 1;
        assert(len_idx < signature_idx);        // Ensure still 'digging' in the PDU
        /* timeAllowedToLive not checked in this implementation */

        // datSet
        tag_idx = (len_idx + 1) + buf[len_idx]; // new tag_idx = (old len_idx + 1 = start of Value field) + old length
        len_idx = tag_idx + 1;
        assert(len_idx < signature_idx);        // Ensure still 'digging' in the PDU
        if (buf[tag_idx] != 0x82)
        {
            std::cerr << "[!] Error: GOOSE datSet Tag\n";
            return false;          
        }

        std::string current_datSet{};
        for (size_t i = 0; i < buf[len_idx]; i++)
        {
            current_datSet += buf[(len_idx + 1) + i];
        }
        if (current_datSet != cbOut.datSetName)
        {
            std::cerr << "[!] Error: datSet mismatch\n";
            return false;          
        }

        // goID
        tag_idx = (len_idx + 1) + buf[len_idx]; // new tag_idx = (old len_idx + 1 = start of Value field) + old length
        len_idx = tag_idx + 1;
        assert(len_idx < signature_idx);        // Ensure still 'digging' in the PDU
        if (buf[tag_idx] != 0x83)
        {
            std::cerr << "[!] Error: GOOSE goID Tag\n";
            return false;          
        }
        std::string current_goID{};
        for (size_t i = 0; i < buf[len_idx]; i++)
        {
            current_goID += buf[(len_idx + 1) + i];
        }
        // Other setups may have a goID different from gocbRef
        // But for this implementation, goID is checked against cbName (= gocbRef)
        if (current_goID != cbOut.cbName)
        {
            std::cerr << "[!] Error: goID mismatch\n";
            return false;          
        }

        // timestamp
        tag_idx = (len_idx + 1) + buf[len_idx]; // new tag_idx = (old len_idx + 1 = start of Value field) + old length
        len_idx = tag_idx + 1;
        assert(len_idx < signature_idx);        // Ensure still 'digging' in the PDU
        /* timestamp not checked in this implementation */

        // stNum
        tag_idx = (len_idx + 1) + buf[len_idx]; // new tag_idx = (old len_idx + 1 = start of Value field) + old length
        len_idx = tag_idx + 1;
        assert(len_idx < signature_idx);        // Ensure still 'digging' in the PDU
        if (buf[tag_idx] != 0x85)
        {
            std::cerr << "[!] Error: GOOSE stNum Tag\n";
            return false;          
        }

        unsigned int current_stNum{};
        for (size_t i = 0; i < buf[len_idx]; i++)
        {
            current_stNum = current_stNum << 8;
            current_stNum += buf[(len_idx + 1) + i];
        }

        // sqNum
        tag_idx = (len_idx + 1) + buf[len_idx]; // new tag_idx = (old len_idx + 1 = start of Value field) + old length
        len_idx = tag_idx + 1;
        assert(len_idx < signature_idx);        // Ensure still 'digging' in the PDU
        if (buf[tag_idx] != 0x86)
        {
            std::cerr << "[!] Error: GOOSE sqNum Tag\n";
            return false;          
        }
        
        unsigned int current_sqNum{};
        for (size_t i = 0; i < buf[len_idx]; i++)
        {
            current_sqNum = current_sqNum << 8;
            current_sqNum += buf[(len_idx + 1) + i];
        }

        // test
        tag_idx = (len_idx + 1) + buf[len_idx]; // new tag_idx = (old len_idx + 1 = start of Value field) + old length
        len_idx = tag_idx + 1;
        assert(len_idx < signature_idx);        // Ensure still 'digging' in the PDU
        if ( (buf[tag_idx] != 0x87) || (buf[len_idx] != 0x01)|| (buf[len_idx + 1] != 0x00) )
        {
            std::cerr << "[!] Error: GOOSE test Tag/Length/Value\n";
            return false;     
        }

        // ConfRev
        tag_idx = (len_idx + 1) + buf[len_idx]; // new tag_idx = (old len_idx + 1 = start of Value field) + old length
        len_idx = tag_idx + 1;
        assert(len_idx < signature_idx);        // Ensure still 'digging' in the PDU
        if ( (buf[tag_idx] != 0x88) || (buf[len_idx] != 0x01) || (buf[len_idx + 1] != 0x01) )
        {
            std::cerr << "[!] Error: GOOSE ConfRev Tag/Length/Value\n";
            return false;     
        }

        // ndsCom
        tag_idx = (len_idx + 1) + buf[len_idx]; // new tag_idx = (old len_idx + 1 = start of Value field) + old length
        len_idx = tag_idx + 1;
        assert(len_idx < signature_idx);        // Ensure still 'digging' in the PDU
        if ( (buf[tag_idx] != 0x89) || (buf[len_idx] != 0x01) || (buf[len_idx + 1] != 0x00) )
        {
            std::cerr << "[!] Error: GOOSE ndsCom Tag/Length/Value\n";
            return false;     
        }

        // numDatSetEntries
        tag_idx = (len_idx + 1) + buf[len_idx]; // new tag_idx = (old len_idx + 1 = start of Value field) + old length
        len_idx = tag_idx + 1;
        assert(len_idx < signature_idx);        // Ensure still 'digging' in the PDU
        if (buf[tag_idx] != 0x8A)
        {
            std::cerr << "[!] Error: GOOSE numDatSetEntries Tag\n";
            return false;     
        }
        int current_numDatSetEntries{buf[len_idx + 1]};

        // allData
        tag_idx = (len_idx + 1) + buf[len_idx]; // new tag_idx = (old len_idx + 1 = start of Value field) + old length
        len_idx = tag_idx + 1;
        assert(len_idx < signature_idx);        // Ensure still 'digging' in the PDU
        if (buf[tag_idx] != 0xAB)
        {
            std::cerr << "[!] Error: GOOSE allData Tag\n";
            return false;         
        }

        std::vector<unsigned char> current_allData{};
        for (size_t i = 0; i < buf[len_idx]; i++)
        {
            current_allData.push_back(buf[len_idx + 1 + i]);
        }

        /* Check: 
         *  stNum, sqNum, numDatSetEntries & allData
         */
        // Check stNum
        if (current_stNum < cbOut.prev_stNum_Value)
        {
            std::cerr << "[!] Error: stNum\n"
                      << "\tExpected stNum: >=" << (cbOut.prev_stNum_Value) << '\n'
                      << "\tObserved stNum: " << current_stNum
                      << "\tObserved sqNum: " << current_sqNum  << '\n';
            return false; 
        }
        // At this point, current stNum >= previous stNum
        if (current_stNum != cbOut.prev_stNum_Value)
        {
            if ( (cbOut.prev_allData_Value == current_allData) 
                && (current_stNum = cbOut.prev_stNum_Value + 1) )
            {
                std::cerr << "[!] Error: stNum incremented but allData not changed\n";
                return false; 
            }
        }
        /* At this point, current stNum > previous stNum + 1 (i.e. some packet(s) lost)
         *            or, current stNum == previous stNum + 1 && allData changed
         *            or, current stNum == previous stNum
         * All these scenarios are acceptable.
         */

        // Check sqNum
        if (current_stNum == cbOut.prev_stNum_Value)
        {
            // Check if sqNum is not increasing
            if (current_sqNum <= cbOut.prev_sqNum_Value && cbOut.prev_sqNum_Value != UINT_MAX)
            {
                std::cerr << "[Info] sqNum reused - suspected duplication.\n"; 
                return false;      
            }
        }
        else
        {
            // Ensure receiver module is run before the sender module (otherwise this error will occur)
            if (current_sqNum != 0)
            {
                std::cerr << "[!] Error: sqNum\n"; 
                return false;  
            }
        }

        // Check numDatSetEntries/allData
        // Indexes were pointing at allData Tag/Length. Reassign to point to Tag/Length of the 1st allData Value.
        tag_idx = len_idx + 1;
        len_idx = tag_idx + 1;
        for (unsigned int i = 0; i < current_numDatSetEntries; i++)
        {
            tag_idx = (len_idx + 1) + buf[len_idx]; // new tag_idx = (old len_idx + 1 = start of Value field) + old length
            len_idx = tag_idx + 1;    
        }
        if (tag_idx != signature_idx)
        {
            std::cerr << "[!] Error: allData Value(s)\n"; 
            return false;           
        }

        // Update output parameter's variables
        cbOut.prev_spduNum = current_spduNum;
        cbOut.prev_stNum_Value = current_stNum;
        cbOut.prev_sqNum_Value = current_sqNum;
        cbOut.prev_numDatSetEntries = current_numDatSetEntries;
        cbOut.prev_allData_Value = current_allData;        
    }
    else if (sess_prot == "SMV")
    {
        /* Assume the following optional fields not present in ASDU:
         *  - datSet
         *  - refrTm
         *  - smpRate
         *  - SmpMod
         */
        if (buf[38] != 0x60 || buf[39] != 0x80)
        {
            std::cerr << "[!] Error: SV PDU Tag\n";
            return false;         
        }

        if ((38 + buf[40]) != signature_idx)
        {
            std::cerr << "[!] Error: SV PDU Length\n";
            return false;         
        }

        if (buf[41] != 0x80 || buf[42] != 0x01 || buf[43] != 0x01)
        {
            std::cerr << "[!] Error: noASDU Tag/Length/Value\n";
            return false;
        }

        if (buf[44] != 0xA2)
        {
            std::cerr << "[!] Error: Sequence-of-ASDUs Tag\n";
            return false;
        }

        if ((44 + buf[45]) != signature_idx)
        {
            std::cerr << "[!] Error: Sequence-of-ASDUs Length\n";
            return false;         
        }

        if (buf[46] != 0x30)
        {
            std::cerr << "[!] Error: ASDU Tag\n";
            return false;  
        }

        if ((46 + buf[47]) != signature_idx)
        {
            std::cerr << "[!] Error: ASDU Length\n";
            return false;         
        }

        // For iterating through the various Tag-Length-Value's of the SV PDU
        size_t tag_idx{};
        size_t len_idx{};

        tag_idx = 48;
        len_idx = tag_idx + 1;
        assert(len_idx < signature_idx);    // Ensure still 'digging' in the PDU
        if (buf[tag_idx] != 0x80)
        {
            std::cerr << "[!] Error: MsvID Tag\n";
            return false; 
        }

        std::string current_svID{};
        for (size_t i = 0; i < buf[len_idx]; i++)
        {
            current_svID += buf[(len_idx + 1) + i];
        }
        if (current_svID != cbOut.cbName)
        {
            std::cerr << "[!] Error: MsvID mismatch\n";
            return false;          
        }

        // smpCnt
        tag_idx = (len_idx + 1) + buf[len_idx]; // new tag_idx = (old len_idx + 1 = start of Value field) + old length
        len_idx = tag_idx + 1;
        assert(len_idx < signature_idx);        // Ensure still 'digging' in the PDU
        if (buf[tag_idx] != 0x82 || buf[len_idx] != 0x02)
        {
            std::cerr << "[!] Error: smpCnt Tag/Length\n";
            return false;
        }

        unsigned int current_smpCnt{};
        for (size_t i = 0; i < buf[len_idx]; i++)
        {
            current_smpCnt = current_smpCnt << 8;
            current_smpCnt += buf[(len_idx + 1) + i];
        }
        if ((current_smpCnt < cbOut.prev_smpCnt_Value) && (cbOut.prev_smpCnt_Value != 3999))
        {
            std::cerr << "[!] Error: smpCnt Value reused\n";
            return false; 
        }

        // confRev
        tag_idx = (len_idx + 1) + buf[len_idx]; // new tag_idx = (old len_idx + 1 = start of Value field) + old length
        len_idx = tag_idx + 1;
        assert(len_idx < signature_idx);        // Ensure still 'digging' in the PDU
        if (buf[tag_idx] != 0x83 || buf[len_idx] != 0x04)
        {
            std::cerr << "[!] Error: confRev Tag/Length\n";
            return false;
        }
        unsigned int current_confRev = (buf[(len_idx + 1)] << 24) + (buf[(len_idx + 2)] << 16)
                                        + (buf[(len_idx + 3)] << 8) + (buf[(len_idx + 4)]);
        if (current_confRev != 0x01)
        {
            std::cerr << "[!] Error: SV ConfRev Value\n";
            return false;     
        }

        // smpSynch
        tag_idx = (len_idx + 1) + buf[len_idx]; // new tag_idx = (old len_idx + 1 = start of Value field) + old length
        len_idx = tag_idx + 1;
        assert(len_idx < signature_idx);        // Ensure still 'digging' in the PDU
        if (buf[tag_idx] != 0x85 || buf[len_idx] != 0x01 || buf[len_idx + 1] != 0x02)
        {
            std::cerr << "[!] Error: smpSynch Tag/Length/Value\n";
            return false;   
        }

        // Sample
        tag_idx = (len_idx + 1) + buf[len_idx]; // new tag_idx = (old len_idx + 1 = start of Value field) + old length
        len_idx = tag_idx + 1;
        assert(len_idx < signature_idx);        // Ensure still 'digging' in the PDU
        if (buf[tag_idx] != 0x87)
        {
            std::cerr << "[!] Error: sequenceofdata Tag\n";
            return false; 
        }

        std::vector<unsigned char> current_seqOfData{};
        for (size_t i = 0; i < buf[len_idx]; i++)
        {
            current_seqOfData.push_back(buf[len_idx + 1 + i]);
        }

        // timestamp
        tag_idx = (len_idx + 1) + buf[len_idx]; // new tag_idx = (old len_idx + 1 = start of Value field) + old length
        len_idx = tag_idx + 1;
        assert(len_idx < signature_idx);        // Ensure still 'digging' in the PDU
        if (buf[tag_idx] != 0x89 || buf[len_idx] != 0x08)
        {
            std::cerr << "[!] Error: timestamp Tag/Length\n";
            return false; 
        }
        /* Checking of timestamp Value not yet included */

        // Update output parameter's variables
        cbOut.prev_spduNum = current_spduNum;
        cbOut.prev_smpCnt_Value = current_smpCnt;
        cbOut.prev_seqOfData_Value = current_seqOfData; 
    }

    return true;
}

// HARDCODING: cbSubscribe[1] -- subscribe the 2nd control block in the vector only
int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        if (argv[0])
            std::cout << "Usage: " << argv[0] << " <SED Filename> <Interface Name to be used on IED> <IED Name>" << '\n';
        else
            // For OS where argv[0] can end up as an empty string instead of the program's name.
            std::cout << "Usage: <program name> <SED Filename> <Interface Name to be used on IED> <IED Name>" << '\n';
            
        return 1;
    }

    // Specify SED Filename
    // Error-checking not included (Assume sed_filename is correct and SED file is well-formed)
    const char *sed_filename = argv[1];

    // Specify Network Interface Name to be used on IED for inter-substation communication
    const char *ifname = argv[2];
    // Save IPv4 address of specified Network Interface into ifreq structure: ifr
    struct ifreq ifr;
    getIPv4Add(ifr, ifname);

    // Specify IED name
    const char *ied_name = argv[3];

    // Specify filename to parse
    std::vector<ControlBlock> vector_of_ctrl_blks = parse_sed(sed_filename);

    // Find relevant Control Blocks to subscribe to
    std::vector<GooseSvData> cbSubscribe{};
    for (const ControlBlock &cb: vector_of_ctrl_blks)
    {
        for (const std::string &stored_ied: cb.subscribingIEDs)
        {
            if (ied_name == stored_ied)
            {
                GooseSvData tmp_goose_sv_data{};
                tmp_goose_sv_data.cbName = cb.cbName;
                tmp_goose_sv_data.cbType = cb.cbType;
                tmp_goose_sv_data.appID = cb.appID;
                tmp_goose_sv_data.multicastIP = cb.multicastIP;

                if (cb.cbType == "GSE")
                    tmp_goose_sv_data.datSetName = cb.datSetName;

                cbSubscribe.push_back(tmp_goose_sv_data);
            }
        }
    }
    
    if (cbSubscribe.size() == 0)
    {
        std::cout << argv[3] << " has no Control Block(s) to subscribe to." << '\n';
        std::cout << "Please check configuration in " << argv[1] << ". Exiting program now...\n";
        return 1;
    }

    UdpSock sock;
    diagnose(sock.isGood(), "Opening datagram socket for receive");

    {
        // enable SO_REUSEADDR to allow multiple instances of this application to
        //    receive copies of the multicast datagrams.
        int reuse = 1;
        diagnose(setsockopt(sock(), SOL_SOCKET, SO_REUSEADDR, (char*)&reuse,
                            sizeof(reuse)) >= 0, "Setting SO_REUSEADDR");
    }

    // Bind to the proper port number with the IP address specified as INADDR_ANY
    sockaddr_in localSock = {};    // initialize to all zeroes
    localSock.sin_family      = AF_INET;
    localSock.sin_port        = htons(IEDUDPPORT);
    localSock.sin_addr.s_addr = INADDR_ANY;
    // Note from manpage that bind returns 0 on success
    diagnose(!bind(sock(), (sockaddr*)&localSock, sizeof(localSock)),
           "Binding datagram socket");

    // Join the multicast group on the local interface.  Note that this
    //    IP_ADD_MEMBERSHIP option must be called for each local interface over
    //    which the multicast datagrams are to be received.
    ip_mreq group = {};    // initialize to all zeroes

    for(int i = 0; i < cbSubscribe.size(); i++)
    {
        // Set multicast IPv4 address in group->imr_multiaddr
        inet_pton(AF_INET, cbSubscribe[i].multicastIP.c_str(), &(group.imr_multiaddr));
        // NOTE: Above statement processes only the 1st subscription requirement 
        // (ok if assume only 1 Control Block to subscribe to)

        // Set local network interface to receive multicast messages
        group.imr_interface = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

        diagnose(setsockopt(sock(), IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&group,
                          sizeof(group)) >= 0, "Adding multicast group");
    }
    // For Circuit-Breaker interlocking mechanism
    unsigned char ownXCBRposition{1};   // 0x01 = Close

    // Keep looping to receive multicast messages
    while(1)
    {
        // Initialization before each reading of socket
        int numbytes{};
        unsigned char buf[MAXBUFLEN]{};
        struct sockaddr_in their_addr{};
        socklen_t addr_len{sizeof their_addr};

        // Read from the socket
        diagnose((numbytes = recvfrom(sock(), buf, MAXBUFLEN-1 , 0, 
                    (struct sockaddr *)&their_addr, &addr_len)) != 1,
                    "\nReading datagram message");

        std::cout << ">> " << numbytes << " bytes received from " 
                    << inet_ntoa(their_addr.sin_addr) << "\n";

        for(int i = 0; i < cbSubscribe.size(); i++)
        {
            /* Start checking UDP payload */
            if (valid_GSE_SMV(buf, numbytes, cbSubscribe[i]))
            {
                if (cbSubscribe[i].cbType == "GSE")
                {
                    std::cout << "Checked R-GOOSE OK\n"
                              << "cbName: " << cbSubscribe[i].cbName << std::endl
                              << "\tallData = {  ";
                    for (unsigned char item : cbSubscribe[i].prev_allData_Value)
                    {
                        std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(item) << "  ";
                    }
                    std::cout << "}\n" << std::dec;
                    std::cout << "\tstNum = " << cbSubscribe[i].prev_stNum_Value 
                              << "\tsqNum = " << cbSubscribe[i].prev_sqNum_Value << "\t|"
                              << "\tSPDU Number (from Session Header) = " << cbSubscribe[i].prev_spduNum << '\n';

                    /* Specific to IED receiving Circuit Breaker position
                     * For Circuit Breaker Interlocking Mechanism
                     */
                    // Check that allData just received is Boolean Tag && 1-byte Length
                    if (cbSubscribe[i].prev_allData_Value[0] == 0x83 
                        && cbSubscribe[i].prev_allData_Value[1] == 0x01)
                    {
                        // Check allData Value
                        if (!cbSubscribe[i].prev_allData_Value[2])
                        {
                            // Fault scenario: output printed at each cycle as long as fault remains
                            std::cout << "[Simulation] Circuit-Breaker interlocking mechanism\n"
                                      << '\t' << cbSubscribe[i].datSetName << " is Open.\n"
                                      << "\tOpen " << ied_name << "$XCBR as well.\n";

                            ownXCBRposition = 0;
                        }
                        else if (ownXCBRposition == 0)
                        {
                            // Non-fault scenario: print output only when there's a change
                            std::cout << "[Simulation] Circuit-Breaker interlocking mechanism\n"
                                      << '\t' << cbSubscribe[i].datSetName << " is Close.\n"
                                      << "\tClose " << ied_name << "$XCBR as well.\n";

                            ownXCBRposition = 1;
                        }
                    }
                    else
                    {
                        std::cout << "[!] GOOSE allData not recognised.\n";
                    }
                }
                else if (cbSubscribe[i].cbType == "SMV")
                {
                    std::cout << "cbName: " << cbSubscribe[i].cbName << std::endl;
                    std::cout << "smpCnt: " << cbSubscribe[i].prev_smpCnt_Value << std::endl;
                    std::cout << "Checked R-SV OK\nsequenceofdata = {  ";
                    std::vector<unsigned int> dataBytes;
                    std::vector<IEEEfloat> seqOfData;
                    IEEEfloat float_value;
                    for (unsigned char item : cbSubscribe[i].prev_seqOfData_Value)
                    {
                        long long unsigned int x = static_cast<int>(item);
                        for(int j = 0; j < std::bitset<8>{x}.size(); j++)
                        {
                            dataBytes.push_back(std::bitset<8>{x}[7-j]);
                        }
                        if(dataBytes.size() == 32)
                        {
                            unsigned int mantissa = convertToInt(dataBytes, 9, 31);
                            float_value.raw.mantissa = mantissa;
                            unsigned int exponent = convertToInt(dataBytes, 1, 8);
                            float_value.raw.exponent = exponent;
                            float_value.raw.sign = dataBytes[0];
                            //std::cout << "float_value:" << float_value.f << std::endl;
                            seqOfData.push_back(float_value);
                            dataBytes.clear();
                        }
                        //std::cout << std::hex << static_cast<int>(item) << " ";
                    }
                    for (IEEEfloat data : seqOfData)
                    {
                        std::cout << std::setprecision(8)<< data.f << " ";
                    }
                    std::cout << "}\n" << std::dec;
                } 
                break;         
            }
            else
            {
                // Ignore the packet and await the next one
                continue;
            }
        }
    }
/*
//Debugging
    for (const GooseSvData &cb: cbSubscribe)
    {
        std::cout << '\n';
        std::cout << "cbName\t: " << cb.cbName << '\n';
        std::cout << "cbType\t: " << cb.cbType << '\n';
        std::cout << "APP ID\t: " << cb.appID << '\n';
        std::cout << "M/C IP\t: " << cb.multicastIP << '\n';
        std::cout << "datSet\t: " << cb.datSetName << '\n';
        std::cout << "SPDU# \t: " << cb.prev_spduNum << '\n';
        std::cout << "stNum \t: " << cb.prev_stNum_Value << '\n';
        std::cout << "sqNum \t: " << cb.prev_sqNum_Value << '\n';
        std::cout << "numDatSetEntries: " << cb.prev_numDatSetEntries << '\n';
        std::cout << '\n';
    }
*/
    return 0;
}
