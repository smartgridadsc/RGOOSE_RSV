/* A collection of data structure and functions for IED operations/debugging */

// GOOSE/SV Data to be tracked per sending/receiving cycle
struct GooseSvData
{
    std::string      cbName{};
    std::string      cbType{};
    std::string      appID{};
    std::string      multicastIP{};
    unsigned int     prev_spduNum{0};
    unsigned int     s_value{0};

    // Specific to GOOSE
    std::string      datSetName{};
    unsigned int     goose_counter{0};
    unsigned int     prev_stNum_Value{0};
    unsigned int     prev_sqNum_Value{0};
    unsigned int     prev_numDatSetEntries{0};
    std::vector<unsigned char> prev_allData_Value{};

    // Specific to SV (Based on IEC 61850-9-2 Light Edition (LE) implementation)
    unsigned int     prev_smpCnt_Value{0};
    std::vector<unsigned char> prev_seqOfData_Value{};
    unsigned int     sv_counter{0};
};

typedef union { 
    float f;
    struct
    { 
        // Order is important.
        // Here the members of the union data structure
        // use the same memory (32 bits).
        // The ordering is taken
        // from the LSB to the MSB.
        unsigned int mantissa : 23;
        unsigned int exponent : 8;
        unsigned int sign : 1; 
    } raw;
} IEEEfloat;

// IPv4 address on ifname is saved into ifreq structure (passed by reference): ifr
void getIPv4Add(struct ifreq &ifr, const char* ifname)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);

    close(fd);
}

/* Function to iterate over the contents of a vector
 * and print all elements using indexing
 */
template <typename T>
void display_vector(const std::vector<T> &vec)
{
    if (vec.size() > 0)
    {
        std::cout << "[ ";
        for (size_t i = 0; i < (vec.size() - 1) ; i++)
        {
            std::cout << vec[i] << ", ";
        }
        std::cout << vec[vec.size() - 1] << " ]";
    }
    else
    {
        std::cout << "Vector is empty!\n";
    }
}

/* Function to print values of variables in a given Control Block */
void printControlBlock(const ControlBlock &ctrl_blk)
{
    std::cout << "\tHost IED \t\t\t= "               << ctrl_blk.hostIED     << '\n';

    std::cout << "\tControl Block type \t\t= "       << ctrl_blk.cbType      << '\n';

    std::cout << "\tMulticast IP Address \t\t= "     << ctrl_blk.multicastIP << '\n';

    std::cout << "\tAPP ID \t\t\t\t= "               << ctrl_blk.appID       << '\n';

    std::cout << "\tVLAN ID \t\t\t= "                << ctrl_blk.vlanID      << '\n';

    std::cout << "\tFully qualified cbName \t\t= "   << ctrl_blk.cbName      << '\n';

    std::cout << "\tFully qualified datSetName \t= " << ctrl_blk.datSetName  << '\n';

    std::cout << "\tInformation Model \t\t= ";
                                        display_vector(ctrl_blk.datSetVector);
    std::cout << '\n';

    std::cout << "\tSubscribing IED(s) \t\t= ";
                                        display_vector(ctrl_blk.subscribingIEDs);
}

/* Function to print a std::vector collection of Control Blocks */
void printCtrlBlkVect(const std::vector<ControlBlock> &vector_of_ctrl_blks)
{
    std::cout << "Total of " << vector_of_ctrl_blks.size() << " Control Block(s) in the following vector:\n";
    std::cout << "    {\n";

    for (size_t i = 0; i < vector_of_ctrl_blks.size() ; i++)
    {
        printControlBlock(vector_of_ctrl_blks[i]);
        if ( i != (vector_of_ctrl_blks.size() - 1) )
        {
            std::cout << "\n    ,\n";
        }
    }
    std::cout << "\n    }\n\n";
}

// Returns the number of bytes to hold a given UINT32 number
unsigned char getUINT32Length(unsigned int num)
{
    if (num < 0x10000)
    {
        if (num < 0x100)
            return 0x01;
        else
            return 0x02;
    }
    else
    {
        if (num < 0x1000000)
            return 0x03;
        else
            return 0x04;
    }
}

// Converts a given UINT32 number into a vector of up to 4 bytes (as output parameter)
void convertUINT32IntoBytes(unsigned int num, std::vector<unsigned char> &vecOut)
{
    const size_t byte_count{getUINT32Length(num)};

    constexpr std::uint_fast32_t mask0 { 0xFF000000 };
    constexpr std::uint_fast32_t mask1 { 0x00FF0000 };
    constexpr std::uint_fast32_t mask2 { 0x0000FF00 };
    constexpr std::uint_fast32_t mask3 { 0x000000FF };

    if (byte_count == 4)
        vecOut.push_back(static_cast<unsigned char>((mask0 & num) >> 24));
    if (byte_count >= 3)
        vecOut.push_back(static_cast<unsigned char>((mask1 & num) >> 16));
    if (byte_count >= 2)
        vecOut.push_back(static_cast<unsigned char>((mask2 & num) >> 8));
    if (byte_count >= 1)
        vecOut.push_back(static_cast<unsigned char>((mask3 & num)));

    assert (vecOut.size() >= 1 && vecOut.size() <= 4);
}

void getHexFromBinary(std::string binaryString, std::vector<unsigned char> &seqOfData_Value)
{
    int result = 0;

    for(size_t count = 0; count < binaryString.length() ; ++count)
    {
        result *=2;
        result += binaryString[count]=='1'? 1 :0;
    }  

    std::stringstream ss;
    ss << "0x" << std::hex << std::setw(2) << std::setfill('0')  << result;

    unsigned int c;
    while (ss >> c)
    {
        seqOfData_Value.push_back(c); 
    }  
}

void convertBinary(int n, int i, std::vector<std::string> &buffer)
{ 
    int k;
    for (k = i - 1; k >= 0; k--) {
 
        if ((n >> k) & 1)
        {
            buffer.push_back("1");
            //cout << "1";
        }
        else
        {
            buffer.push_back("0");
            //cout << "0";
        }
    }
}

unsigned int convertToInt(std::vector<unsigned int> dataBytes, int low,int high)
{
    unsigned int f=0,i;
    for(i = high; i>= low; i--)
    {
        f = f + dataBytes[i] * pow(2, high - i);
    }
    return f;
} 

void convertIEEE(IEEEfloat var, std::vector<unsigned char> &seqOfData_Value)
{
    std::vector<std::string> buffer{};
    // add sign bit
    if(var.raw.sign){
        buffer.push_back("1");
    }
    else
    {
        buffer.push_back("0");
    }
    // convert float to binary
    convertBinary(var.raw.exponent, 8, buffer);
    convertBinary(var.raw.mantissa, 23, buffer);
    for (int i =0; i< buffer.size(); i++)
    {
        if ((i+1) % 8 == 0)
        {
            std::string binaryString = buffer[i-7] + buffer[i-6] + buffer[i-5] + buffer[i-4] +
                                  buffer[i-3] + buffer[i-2] + buffer[i-1] + buffer[i];
            //push hex data of float value into seqOfData_Value 8 bit by 8 bit.
            getHexFromBinary(binaryString, seqOfData_Value);
            
        }
    }
}
