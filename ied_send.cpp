#include <algorithm>
#include <array>
#include <cctype>
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
#include <iostream>
#include <fstream>

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

using namespace std;

// Set timestamp in an 8-byte array
void set_timestamp(std::array<unsigned char, 8> &timeArrOut)
{
    auto nanosec_since_epoch = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto sec_since_epoch = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

    unsigned int subsec_component = nanosec_since_epoch - (sec_since_epoch * 1'000'000'000);
    double frac_sec{static_cast<double>(subsec_component)};

    // Convert from [nanosecond] to [second]
    for (int i = 0; i < 9; i++)
    {
        frac_sec = frac_sec / 10;
    }

    // Convert to 3-byte (24-bit) fraction of second value (ref: ISO 9506-2)
    for (int i = 0; i < 24; i++)
    {
        frac_sec = frac_sec * 2;
    }

    frac_sec = round(frac_sec);
    subsec_component = static_cast<unsigned int>(frac_sec);

    // Set integer seconds in array's high order octets (0 to 3)
    for (std::size_t i{ 0 }; i < (timeArrOut.size() / 2); i++)
    {
        timeArrOut[i] = static_cast<int>((sec_since_epoch >> (24 - 8 * i)) & 0xff);
    }

    // Set fractional second in array's octets 4 to 6
    for (std::size_t i{ timeArrOut.size() / 2 }; i < (timeArrOut.size() - 1); i++)
    {
        timeArrOut[i] = static_cast<int>(subsec_component >> (16 - 8 * (i - timeArrOut.size() / 2)) & 0xff);
    }

    /*
    // DEBUGGING: For digging into the workings of timestamp
    std::cout << std::dec;
    std::cout << "seconds since epoch: \t " << sec_since_epoch << '\n';
    std::cout << "nanoseconds since epoch: " << nanosec_since_epoch << "\n\n";

    std::cout << "round(frac_sec * 2^24): " << std::fixed << frac_sec << '\n';
    std::cout << "frac_sec (integer): " << std::hex << subsec_component << "\n\n";

    for (std::size_t i{ 0 }; i < timeArrOut.size(); i++)
    {
        std::cout << "timeArrOut[" << i << "]: " << std::setfill('0') << std::setw(2) << static_cast<int>(timeArrOut[i]) << '\n';
    }
    */
}

// Set GOOSE allData value in output parameter
void set_gse_hardcoded_data(std::vector<unsigned char> &allDataOut, GooseSvData &goose_data, bool loop_data)
{
    //static int s_value{0};

    /* GOOSE data set encoded based on the MMS adapted ASN.1/BER rule */
    // Tag = 0x83 -> Data type: Boolean
    allDataOut.push_back(0x83);

    // Length = 0x01
    allDataOut.push_back(0x01);

    // Value = 0x00 -> Circuit breaker is Open
    //       = 0x01 -> Circuit breaker is Close
 
    int i=0, c=0;
    string line;
    unsigned int goose_counter = goose_data.goose_counter;
    fstream datafile;
    
    datafile.open("GOOSEdata.txt");
    if (!datafile.is_open())
    {
        cout << "Failure to open." << endl;
    }
    while(goose_counter > 0)
    {
        getline(datafile,line);
        goose_counter--;
    }
   
    c = line.length();
    // ensure data provided is not empty
    assert(c!=0);
    for (int i = 1; i<line.length();i++)
    { 
	if (line.at(i) == ' ')
	{
	   c--;
	}
    }
    line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());
    datafile.close();
    cout << "Number of characters: "<< c << endl;
    
    unsigned int s_value;
    if (loop_data)
    {
        s_value = goose_data.s_value % c;
    }
    else
    {
        s_value = goose_data.s_value; 
    }
    // prevent overflow
    //assert(s_value < c);
   
    cout<<"GOOSEdata file values are: ";
    for (int i = 0; i < line.length(); i++)
        cout << line[i] << ", ";
        cout << endl;

    if (line[s_value] == '0')
    {
        //cout <<"pushed 0" << endl;
        allDataOut.push_back(0x00);
    }
    else
    {
        //cout <<"pushed 1" << endl;
        allDataOut.push_back(0x01);
    }

    // Circuit breaker closed during cycles 10-14
    //if (s_value >= 10 && s_value < 15)
    //{
    //    allDataOut.push_back(0x00);
    //}
    //else
    //{
    //    allDataOut.push_back(0x01);
    //}

    /* [For Demo Purpose] 
     * Add 2-sec delay just before sending the 21st packet (s_value = 20)
     * Facilitate demonstration of attacker using this attack window
     */
    //if (s_value == 25)
    //{
        //sleep(2);
    //}
    
    // Ensure allData field has only the 3 bytes hardcoded from this function
    assert (allDataOut.size() == 3);
}


void set_sv_hardcoded_data(std::vector<unsigned char> &seqOfData_Value, GooseSvData &sv_data, bool loop_data)
{
    int i=0, v=0, counter=0;
    string line, value;
    unsigned int sv_counter = sv_data.sv_counter;
    fstream datafile;

    datafile.open("SVdata.txt");
    if (!datafile.is_open())
    {
        cout << "Failure to open." << endl;
    }
    while(sv_counter > 0)
    {
        getline(datafile,line);
        sv_counter--;
    }
    
    // using whitespace to count the number of values
    for (int i = 1; i<line.length();i++)
    { 
	if (line.at(i) == ' ')
	{
	   v++;
	}
    }
    v += 1;
    
    datafile.close();
    
    // ensure there are 4 voltage + 4 degree, 4 current + 4 degree values
    //assert(v%16 == 0);
    
    std::istringstream iss(line);
    IEEEfloat float_value;
    
    unsigned int s_value;
    
    if (loop_data)
    {
        s_value = sv_data.s_value % (v/16);
    }
    else
    {
        s_value = sv_data.s_value; 
    }
    
    s_value *= 16;
    
    while(s_value > 0)
    {
        iss >> value;
        s_value--;
    }
    
    cout << "SVdata file values are: ";
    
    while(iss >> value && counter != 16)
    {
    	cout << value << ", ";
        float_value.f = stof(value);
        convertIEEE(float_value, seqOfData_Value);
        counter++;
    }
    
    cout << endl;
    //cout << "SVdata file values are: ";
    
    //for (i = 0; i < seqOfData_Value.size(); i++)
    //    cout << seqOfData_Value[i] << ", ";
    //    cout << endl;
    
    // Ensure seqOfData_Value field has only the 64 bytes hardcoded from this function
    assert (seqOfData_Value.size() == 64);
}

/* Function to form the GOOSE PDU */
// "Returns" out parameter: pduOut (newly initialized by caller before passed in)
void form_goose_pdu(GooseSvData &goose_data, std::vector<unsigned char> &pduOut)
{
    /* Initialize variables for GOOSE PDU data */
    unsigned char goosePDU_Tag{0x61};
    unsigned char goosePDU_Tag2{0x81};
    unsigned char goosePDU_Len{};         // Includes GOOSE PDU Tag & Len and every component's length

        // *** GOOSE PDU -> gocbRef ***
        unsigned char gocbRef_Tag{0x80};
        unsigned char gocbRef_Len{static_cast<unsigned char>(goose_data.cbName.length())};  // Maximum size of 65 bytes by specification
        std::vector<unsigned char> gocbRef_Value{goose_data.cbName.begin(), goose_data.cbName.end()};

        // *** GOOSE PDU -> timeAllowedToLive (in ms) ***
        unsigned char timeAllowedToLive_Tag{0x81};
        unsigned char timeAllowedToLive_Len{};
        unsigned int timeAllowedToLive_Value{};             // Depends on sqNum

        // *** GOOSE PDU -> datSet ***
        unsigned char datSet_Tag{0x82};
        unsigned char datSet_Len{static_cast<unsigned char>(goose_data.datSetName.length())};   // Maximum size of 65 bytes by specification
        std::vector<unsigned char> datSet_Value{goose_data.datSetName.begin(), goose_data.datSetName.end()};

        // *** GOOSE PDU -> goID ***
        unsigned char goID_Tag{0x83};
        unsigned char goID_Len{static_cast<unsigned char>(goose_data.cbName.length())};  // Maximum size of 65 bytes by specification
        std::vector<unsigned char> goID_Value{goose_data.cbName.begin(), goose_data.cbName.end()};

        // *** GOOSE PDU -> t ***
        unsigned char time_Tag{0x84};
        const unsigned char time_Len{0x08};
        /*
         * Bit 7 = 0: Leap Second NOT Known
         * Bit 6 = 0: Not ClockFailure
         * Bit 5 = 0: Clock Synchronized
         * Bits 4-0 = 01010: 10-bits of accuracy [HARDCODING]
         */
        std::array<unsigned char, time_Len> time_Value{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0a};

        // *** GOOSE PDU -> stNum ***
        unsigned char stNum_Tag{0x85};
        unsigned char stNum_Len{};
        unsigned int stNum_Value{};

        // *** GOOSE PDU -> sqNum ***
        unsigned char sqNum_Tag{0x86};
        unsigned char sqNum_Len{};
        unsigned int sqNum_Value{};

        // *** GOOSE PDU -> test ***
        unsigned char test_Tag{0x87};
        const unsigned char test_Len{1};
        unsigned char test_Value{0};        // 0 = Boolean false

        // *** GOOSE PDU -> confRev ***
        unsigned char confRev_Tag{0x88};
        unsigned char confRev_Len{1};       // Len = 1 since value is fixed as 1
        unsigned char confRev_Value{1};     // [Deviation] UINT32 type by specification
                                            // - specifying the number of times configuration of data set has been changed

        // *** GOOSE PDU -> ndsCom ***
        unsigned char ndsCom_Tag{0x89};
        const unsigned char ndsCom_Len{1};
        unsigned char ndsCom_Value{0};      // 0 = Boolean false (does not need commissioning)

        // *** GOOSE PDU -> numDatSetEntries ***
        unsigned char numDatSetEntries_Tag{0x8A};
        unsigned char numDatSetEntries_Len{1};
        unsigned char numDatSetEntries_Value{1};  // depends on how many data attributes to include (fix to 1 as of now)

        // *** GOOSE PDU -> allData ***
        unsigned char allData_Tag{0xAB};
        unsigned char allData_Len{};
        std::vector<unsigned char> allData_Value{};

    // *** start forming GOOSE PDU from bottom of structure ***
    //     because some components at the top are dependent on others at the bottom

    // (xii) get allData value from database
    set_gse_hardcoded_data(allData_Value, goose_data, true);  // To be replaced when implementing database access
    allData_Len = allData_Value.size();

    // (viii) to (xi) no changes from initialization

    // (vi) stNum & (vii) Set sqNum
    bool stateChanged{goose_data.prev_allData_Value != allData_Value};
    if (stateChanged)
    {
        // Update current stNum_Value when data value changed
        //  and also update the historical record in preparation for next cycle
        stNum_Value = ++goose_data.prev_stNum_Value;

        // 0 is reserved for the 1st transmission of a StNum change
        sqNum_Value = 0;
        goose_data.prev_sqNum_Value = 0;
    }
    else
    {
        // No increment of stNum when data value not changed
        stNum_Value = goose_data.prev_stNum_Value;

        // Increment sqNum
        if (goose_data.prev_sqNum_Value != UINT_MAX)
        {
            // Increment for each transmission of the same stNum
            //  and also update the historical record in preparation for next cycle
            sqNum_Value = ++goose_data.prev_sqNum_Value;
        }
        else
        {
            // rolls over to value of 1
            sqNum_Value = 1;
            goose_data.prev_sqNum_Value = 1;
        }

    }
    sqNum_Len = getUINT32Length(sqNum_Value);
    stNum_Len = getUINT32Length(stNum_Value);

    // (v) t (i.e. UTC time stamp)
    set_timestamp(time_Value);

   // (iii) datSet & (iv) goID no changes from initialization

    // (ii) timeAllowedToLive (in milliseconds)
    if (sqNum_Value <= 5)
    {
        timeAllowedToLive_Value = 20;   // 0x14
        timeAllowedToLive_Len = 0x01;
    }
    else if (sqNum_Value == 6)
    {
        timeAllowedToLive_Value = 32;   // 0x20
        timeAllowedToLive_Len = 0x01;
    }
    else if (sqNum_Value == 7)
    {
        timeAllowedToLive_Value = 64;   // 0x40
        timeAllowedToLive_Len = 0x01;
    }
    else if (sqNum_Value == 8)
    {
        timeAllowedToLive_Value = 128;
        timeAllowedToLive_Len = 0x01;   // 0x80
    }
    else if (sqNum_Value == 9)
    {
        timeAllowedToLive_Value = 256;  // 0x0100
        timeAllowedToLive_Len = 0x02;
    }
    else if (sqNum_Value == 10)
    {
        timeAllowedToLive_Value = 512;  // 0x0200
        timeAllowedToLive_Len = 0x02;
    }
    else if (sqNum_Value == 11)
    {
        timeAllowedToLive_Value = 1024; // 0x0400
        timeAllowedToLive_Len = 0x02;
    }
    else if (sqNum_Value == 12)
    {
        timeAllowedToLive_Value = 2048; // 0x0800
        timeAllowedToLive_Len = 0x02;
    }
    else if (sqNum_Value >= 13)
    {
        timeAllowedToLive_Value = 4000; // 0x0FA0
        timeAllowedToLive_Len = 0x02;
    }

    // (i) gocbRef no changes from initialization


    /* Fill up pduOut for "returning" */
    pduOut.push_back(goosePDU_Tag);     // index 0
    pduOut.push_back(goosePDU_Tag2);    // index 1
    pduOut.push_back(goosePDU_Len);     // index 2: here, GOOSE PDU Length is not yet computed/assigned

    pduOut.push_back(gocbRef_Tag);
    pduOut.push_back(gocbRef_Len);
    pduOut.insert(pduOut.end(), gocbRef_Value.begin(), gocbRef_Value.end());

    pduOut.push_back(timeAllowedToLive_Tag);
    pduOut.push_back(timeAllowedToLive_Len);
    std::vector<unsigned char> timeAllowedToLive_ValVec{};
    convertUINT32IntoBytes(timeAllowedToLive_Value, timeAllowedToLive_ValVec);
    pduOut.insert(pduOut.end(), timeAllowedToLive_ValVec.begin(), timeAllowedToLive_ValVec.end());

    pduOut.push_back(datSet_Tag);
    pduOut.push_back(datSet_Len);
    pduOut.insert(pduOut.end(), datSet_Value.begin(), datSet_Value.end());

    pduOut.push_back(goID_Tag);
    pduOut.push_back(goID_Len);
    pduOut.insert(pduOut.end(), goID_Value.begin(), goID_Value.end());

    pduOut.push_back(time_Tag);
    pduOut.push_back(time_Len);
    pduOut.insert(pduOut.end(), time_Value.begin(), time_Value.end());

    pduOut.push_back(stNum_Tag);
    pduOut.push_back(stNum_Len);
    std::vector<unsigned char> stNum_ValVec{};
    convertUINT32IntoBytes(stNum_Value, stNum_ValVec);
    pduOut.insert(pduOut.end(), stNum_ValVec.begin(), stNum_ValVec.end());

    pduOut.push_back(sqNum_Tag);
    pduOut.push_back(sqNum_Len);
    std::vector<unsigned char> sqNum_ValVec{};
    convertUINT32IntoBytes(sqNum_Value, sqNum_ValVec);
    pduOut.insert(pduOut.end(), sqNum_ValVec.begin(), sqNum_ValVec.end());

    pduOut.push_back(test_Tag);
    pduOut.push_back(test_Len);
    pduOut.push_back(test_Value);

    pduOut.push_back(confRev_Tag);
    pduOut.push_back(confRev_Len);
    pduOut.push_back(confRev_Value);

    pduOut.push_back(ndsCom_Tag);
    pduOut.push_back(ndsCom_Len);
    pduOut.push_back(ndsCom_Value);

    pduOut.push_back(numDatSetEntries_Tag);
    pduOut.push_back(numDatSetEntries_Len);
    pduOut.push_back(numDatSetEntries_Value);

    pduOut.push_back(allData_Tag);
    pduOut.push_back(allData_Len);
    pduOut.insert(pduOut.end(), allData_Value.begin(), allData_Value.end());

    pduOut[2] = pduOut.size();

    // Update historical allData before exiting function
    goose_data.prev_allData_Value = allData_Value;
}

/* Function to form the SV PDU */
// "Returns" out parameter: pduOut (newly initialized by caller before passed in)
void form_sv_pdu(GooseSvData &sv_data, std::vector<unsigned char> &pduOut)
{
    /* Initialize variables for SV PDU data */
    unsigned char svPDU_Tag{0x60};
    unsigned char svPDU_Tag2{0x80};
    unsigned char svPDU_Len{};         // Includes SV PDU Tag & Len and every component's length

    unsigned char noASDU_Tag{0x80};
    unsigned char noASDU_Len{0x01};
    unsigned char noASDU_Value{0x01};   // Fixed as 1 for IEC 61850-9-2 LE implementation

    unsigned char seqOfASDU_Tag{0xA2};
    unsigned char seqOfASDU_Len{};

    // *** SV ASDU ***
    unsigned char asdu_Tag{0x30};
    unsigned char asdu_Len{};

        // *** SV ASDU -> MsvID ***
        unsigned char svID_Tag{0x80};
        unsigned char svID_Len{static_cast<unsigned char>(sv_data.cbName.length())};
        std::vector<unsigned char> svID_Value{sv_data.cbName.begin(), sv_data.cbName.end()};

        // *** SV ASDU -> smpCnt ***
        unsigned char smpCnt_Tag{0x82};
        unsigned char smpCnt_Len{0x02};
        unsigned int smpCnt_Value{};

        // *** SV ASDU -> confRev ***
        unsigned char confRev_Tag{0x83};
        unsigned char confRev_Len{0x04};
        unsigned int confRev_Value{};

        // *** SV ASDU -> smpSynch ***
        unsigned char smpSynch_Tag{0x85};
        unsigned char smpSynch_Len{0x01};
        unsigned char smpSynch_Value{};

        // *** SV ASDU -> Sample ***
        unsigned char seqOfData_Tag{0x87};
        unsigned char seqOfData_Len{};
        std::vector<unsigned char> seqOfData_Value{};

        // *** SV PDU -> t ***
        unsigned char time_Tag{0x89};
        const unsigned char time_Len{0x08};
        /*
         * Bit 7 = 0: Leap Second NOT Known
         * Bit 6 = 0: Not ClockFailure
         * Bit 5 = 0: Clock Synchronized
         * Bits 4-0 = 01010: 10-bits of accuracy [HARDCODING]
         */
        std::array<unsigned char, time_Len> time_Value{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0a};

    // Set smpCnt Value (assume 50Hz)
    if (sv_data.prev_smpCnt_Value != 3999)
    {
        smpCnt_Value = sv_data.prev_smpCnt_Value++;
    }
    else
    {
        smpCnt_Value = 0;
        sv_data.prev_smpCnt_Value = 0;
    }

    // Set confRev Value
    confRev_Value = 1;

    // Set smpSynch Value (fixed as 2 in this implementation)
    /* As per IEC 61850-9-2:
     * 0           = SV are not synchronised by an external clock signal.
     * 1           = SV are synchronised by a clock signal from an unspecified local area clock.
     * 2           = SV are synchronised by a global area clock signal (time traceable).
     * 5 to 254    = SV are synchronised by a clock signal from a local area clock identified by this value.
     * 3 to 4, 255 = Reserved values – Do not use.
     */
    smpSynch_Value = 0x02;

    // Set seqOfData
    // HARDCODED Sample Data in this implementation
    /*seqOfData_Value = {0x10, 0x14, 0x12, 0x15, 0x12, 0x64, 0x11, 0x12, 0x18, 0x22, 0x14, 0x12, 0x17, 0x16, 0x30, 0x42,
                       0x10, 0x14, 0x12, 0x15, 0x12, 0x64, 0x11, 0x12, 0x18, 0x22, 0x14, 0x12, 0x17, 0x16, 0x30, 0x42,
                       0x10, 0x14, 0x12, 0x15, 0x12, 0x64, 0x11, 0x12, 0x18, 0x22, 0x14, 0x12, 0x17, 0x16, 0x80, 0xDA, 
                       0x80, 0x60, 0x0C, 0x2D, 0x01, 0x03, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    */
    
    
    set_sv_hardcoded_data(seqOfData_Value, sv_data, true);
    
    seqOfData_Len = seqOfData_Value.size();

    // Set timestamp
    set_timestamp(time_Value);

    /* At this point, the ASDU is complete.
     * So, start filling up a temp vector with ASDU and get ASDU's length first.
     * Then, encapsulate with other encoding to complete the entire PDU.
     */
    std::vector<unsigned char> tmpVec{};
    tmpVec.push_back(asdu_Tag);     // index 0 of tmpVec
    tmpVec.push_back(asdu_Len);     // index 1 of tmpVec: not yet computed

    tmpVec.push_back(svID_Tag);     // index 2 of tmpVec
    tmpVec.push_back(svID_Len);
    tmpVec.insert(tmpVec.end(), svID_Value.begin(), svID_Value.end());

    tmpVec.push_back(smpCnt_Tag);
    tmpVec.push_back(smpCnt_Len);
    std::vector<unsigned char> smpCnt_ValVec{};
    convertUINT32IntoBytes(smpCnt_Value, smpCnt_ValVec);
    assert ((smpCnt_ValVec.size() > 0) && (smpCnt_ValVec.size() <= 2));
    if (smpCnt_ValVec.size() == 1)
        tmpVec.push_back(0x00); // Pad with a higher order byte 0x00 to ensure condition (smpCnt_Len == 2)
    tmpVec.insert(tmpVec.end(), smpCnt_ValVec.begin(), smpCnt_ValVec.end());

    tmpVec.push_back(confRev_Tag);
    tmpVec.push_back(confRev_Len);
    tmpVec.push_back(static_cast<unsigned char>( (confRev_Value >> 24) & 0xFF ));
    tmpVec.push_back(static_cast<unsigned char>( (confRev_Value >> 16) & 0xFF ));
    tmpVec.push_back(static_cast<unsigned char>( (confRev_Value >>  8) & 0xFF ));
    tmpVec.push_back(static_cast<unsigned char>( (confRev_Value      ) & 0xFF ));

    tmpVec.push_back(smpSynch_Tag);
    tmpVec.push_back(smpSynch_Len);
    tmpVec.push_back(smpSynch_Value);

    tmpVec.push_back(seqOfData_Tag);
    tmpVec.push_back(seqOfData_Len);
    tmpVec.insert(tmpVec.end(), seqOfData_Value.begin(), seqOfData_Value.end());    

    tmpVec.push_back(time_Tag);
    tmpVec.push_back(time_Len);
    tmpVec.insert(tmpVec.end(), time_Value.begin(), time_Value.end());

    // Set ASDU Length
    tmpVec[1] = tmpVec.size();

    /* At this point, the sequence of (one) ASDU is complete, i.e. tmpVec
     * So, start filling up pduOut with required encoding for the SV PDU.
     * Then, append the tmpVec at the end to complete the SV PDU.
     */
    seqOfASDU_Len = tmpVec.size() + 2;
    svPDU_Len = seqOfASDU_Len + 6;

    pduOut.push_back(svPDU_Tag);
    pduOut.push_back(svPDU_Tag2);
    pduOut.push_back(svPDU_Len);

    pduOut.push_back(noASDU_Tag);       // 0x80
    pduOut.push_back(noASDU_Len);       // 0x01
    pduOut.push_back(noASDU_Value);     // 0x01

    pduOut.push_back(seqOfASDU_Tag);
    pduOut.push_back(seqOfASDU_Len);
    pduOut.insert(pduOut.end(), tmpVec.begin(), tmpVec.end());

    // Update historical allData before exiting function
    sv_data.prev_seqOfData_Value = seqOfData_Value;   
}

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

    /* DEBUGGING CODE: check Control Blocks parsed from SED file */
    // printCtrlBlkVect(vector_of_ctrl_blks);

    // Find relevant Control Blocks pertaining to IED
    std::vector<GooseSvData> ownControlBlocks{};
    unsigned int goose_counter{0}, sv_counter{0};
    for (std::vector<ControlBlock>::const_iterator it = vector_of_ctrl_blks.cbegin(); it != vector_of_ctrl_blks.cend(); ++it)
    {
        if ((*it).hostIED == ied_name)
        {
            if ((*it).cbType == "GSE")
            {
                goose_counter++;
                GooseSvData tmp_goose_data{};

                tmp_goose_data.cbName = (*it).cbName;
                tmp_goose_data.cbType = (*it).cbType;
                tmp_goose_data.appID = (*it).appID;
                tmp_goose_data.multicastIP = (*it).multicastIP;
                tmp_goose_data.datSetName = (*it).datSetName;
                tmp_goose_data.goose_counter = goose_counter;
                
                ownControlBlocks.push_back(tmp_goose_data);
            }
            else if ((*it).cbType == "SMV")
            {
                sv_counter++;
                GooseSvData tmp_sv_data{};

                tmp_sv_data.cbName = (*it).cbName;
                tmp_sv_data.cbType = (*it).cbType;
                tmp_sv_data.appID = (*it).appID;
                tmp_sv_data.multicastIP = (*it).multicastIP;
                tmp_sv_data.sv_counter = sv_counter;

                ownControlBlocks.push_back(tmp_sv_data);                
            }
        }
    }

    // Keep looping to send multicast messages
    unsigned int s_value{0}; 
    while(1)
    {
        // sleep(1);            // in seconds
        usleep(1'000'000);      // in microseconds
        // Form network packet for each Control Block
        
        for (size_t i = 0; i < ownControlBlocks.size(); i++)
        {
            // For forming Payload in Application Profile
            std::vector<unsigned char> payload{};
            

            // PDU will be part of Payload
            std::vector<unsigned char> pdu{};

            if (ownControlBlocks[i].cbType == "GSE")
            {
                std::cout << "cbName " << ownControlBlocks[i].cbName << endl;
                ownControlBlocks[i].s_value = s_value;
                form_goose_pdu(ownControlBlocks[i], pdu);

                // Payload Type 0x81: non-tunneled GOOSE APDU
                payload.push_back(0x81);
            }
            else if (ownControlBlocks[i].cbType == "SMV")
            {
                std::cout << "cbName " << ownControlBlocks[i].cbName << endl;
                ownControlBlocks[i].s_value = s_value;
                form_sv_pdu(ownControlBlocks[i], pdu);

                // Payload Type 0x82: non-tunneled SV APDU
                payload.push_back(0x82);
            }

            /* Continue forming Payload */
            // Simulation 0x00: Boolean False = payload not sent for test
            payload.push_back(0x00);

            // APP ID
            unsigned long raw_converted_appid = std::stoul(ownControlBlocks[i].appID,nullptr,16);
            payload.push_back(static_cast<unsigned char>( (raw_converted_appid >> 8) & 0xFF ));
            payload.push_back(static_cast<unsigned char>( (raw_converted_appid     ) & 0xFF ));

            // APDU Length
            size_t apdu_len{pdu.size() + 2};  // Length of SV or GOOSE PDU plus the APDU Length field itself
            payload.push_back(static_cast<unsigned char>( (apdu_len >> 8) & 0xFF ));
            payload.push_back(static_cast<unsigned char>( (apdu_len     ) & 0xFF ));

            // PDU
            payload.insert(payload.end(), pdu.begin(), pdu.end());  // Payload completely formed here

            /* Based on RFC-1240 protocol (OSI connectionless transport services on top of UDP) */
            std::vector<unsigned char> udp_data{};
            // Length Identifier (LI)
            udp_data.push_back(0x01);
            // Transport Identifier (TI)
            udp_data.push_back(0x40);

            /* Based on IEC 61850-90-5 session protocol specification */
            // Session Identifier (SI)
            if (ownControlBlocks[i].cbType == "GSE")
            {
                udp_data.push_back(0xA1);   // 0xA1: non-tunneled GOOSE APDU
            }
            else if (ownControlBlocks[i].cbType == "SMV")
            {
                udp_data.push_back(0xA2);   // 0xA2: non-tunneled SV APDU
            }

            // Length Identifier (LI)
            udp_data.push_back(0x18);   // 0x18 => 24 bytes = CommonHeader [1 byte] + LI [1 byte] + (SPDU Length + ... + Key ID) [22 bytes]

            // Common session header
            udp_data.push_back(0x80);   // Parameter Identifier (PI) of 0x80 as per IEC 61850-90-5

            // Length Identifier (LI)
            udp_data.push_back(0x16);   // 0x16 => 22 bytes = (SPDU Length + ... + Version Number) [10 bytes] + (Time of current key + ... + Key ID) [12 bytes]

            // SPDU Length (fixed size 4-byte word with maximum value of 65,517)
            /*
             * SPDU Number:             4 bytes
             * Version Number:          2 bytes
             * Security Information:   12 bytes
             * Payload Length:          4 bytes
             * Payload:                (as formed)
             * Signature:               2 bytes (signature production not considered => only 1-byte Tag + 1-byte Length
             */
            unsigned int spdu_length = (4 + 2) + 12 + 4 + payload.size() + 2;
            udp_data.push_back(static_cast<unsigned char>( (spdu_length >> 24) & 0xFF ));
            udp_data.push_back(static_cast<unsigned char>( (spdu_length >> 16) & 0xFF ));
            udp_data.push_back(static_cast<unsigned char>( (spdu_length >>  8) & 0xFF ));
            udp_data.push_back(static_cast<unsigned char>( (spdu_length      ) & 0xFF ));

            // SPDU Number (fixed size 4-byte unsigned integer word)
            unsigned int current_SPDUNum = ownControlBlocks[i].prev_spduNum++;
            udp_data.push_back(static_cast<unsigned char>( (current_SPDUNum >> 24) & 0xFF ));
            udp_data.push_back(static_cast<unsigned char>( (current_SPDUNum >> 16) & 0xFF ));
            udp_data.push_back(static_cast<unsigned char>( (current_SPDUNum >>  8) & 0xFF ));
            udp_data.push_back(static_cast<unsigned char>( (current_SPDUNum      ) & 0xFF ));

            // Version Number (fixed 2-byte unsigned integer, assigned to 1 in this implementation)
            udp_data.push_back(0x00);
            udp_data.push_back(0x01);

            // Security Information (not used in this implementation, hence set to 0's)
            /* Time of current key: 4 bytes
             * Time to next key:    2 bytes
             * Security Algorithm:  2 bytes
             * Key ID:              4 bytes
             * ----------------------------
             * TOTAL:              12 bytes
             */
            for (size_t j{0}; j < 12; ++j)
            {
                udp_data.push_back(0x00);
            }

            // Form the Session User Information: prepend Payload Length to & append Signature to the Payload
            // Payload Length (fixed size 4-byte unsigned integer with maximum value of 65,399
            size_t payload_len{payload.size() + 4};  // Length of Payload plus Payload Length field itself
            udp_data.push_back(static_cast<unsigned char>( (payload_len >> 24) & 0xFF ));
            udp_data.push_back(static_cast<unsigned char>( (payload_len >> 16) & 0xFF ));
            udp_data.push_back(static_cast<unsigned char>( (payload_len >>  8) & 0xFF ));
            udp_data.push_back(static_cast<unsigned char>( (payload_len      ) & 0xFF ));

            udp_data.insert(udp_data.end(), payload.begin(), payload.end());

            // Signature Tag = 0x85
            udp_data.push_back(0x85);

            // Length of HMAC considered as zero in this implementation
            udp_data.push_back(0x00);   // Application Profile = UDP Data completely formed here


            // Send via UDP multicast (ref: udpSock.hpp)
            UdpSock sock;
            diagnose(sock.isGood(), "Opening datagram socket for send");

            // Set multicast protocol network parameters
            sockaddr_in groupSock = {};   // init to all zeroes
            groupSock.sin_family = AF_INET;
            groupSock.sin_port = htons(IEDUDPPORT);
            inet_pton(AF_INET, ownControlBlocks[i].multicastIP.c_str(), &(groupSock.sin_addr));

            // Set local network interface to send multicast messages
            in_addr localIface = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

            diagnose(setsockopt(sock(), IPPROTO_IP, IP_MULTICAST_IF, (char*)&localIface,
                              sizeof(localIface)) >= 0, "Setting local interface");

            // Set TTL
            int ttl = 16;
            diagnose(setsockopt(sock(), IPPROTO_IP, IP_MULTICAST_TTL, &ttl, 
                              sizeof(ttl)) >= 0, "Setting TTL");
            
            diagnose(sendto(sock(), &udp_data[0], udp_data.size(), 0,
                          (sockaddr*)&groupSock, sizeof(groupSock)) >= 0,
                   "Sending datagram message");
        }
        s_value++;
    }

    return 0;
}
