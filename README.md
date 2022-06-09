## R-GOOSE / R-SV Send and Receive Example

The scripts here simulate the sending and receiving of R-GOOSE and R-SV data using UDP multicasting.  

The data is supplied from the text files GOOSEdata.txt and SVdata.txt. 

### Building

Run "make" to build the ied_recv and ied_send executables.


### Running

1) Start receiving on one terminal:  
   sudo ./build/ied_recv sample.sed enp0s3 S2_IED0

2) Start sending on another terminal:  
   sudo ./build/ied_send sample.sed enp0s3 S1_IED22

Note:
- Replace "enp0s3" with the interface you are using.
- The scripts run_recv.sh and run_send.sh can be used in place of the above.
- The data rows (GOOSE and SV) correspond to the GSE and SMV modules defined in the sample.sed file.
- The number of columns in SVdata.txt is fixed at 16.
  The columns represent 4 sets of:
  - voltage magnitude
  - voltage angle
  - current magnitude
  - current angle
- After the end of data for both GOOSE and SV, the send script will loop from the beginning.
