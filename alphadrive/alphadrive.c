// TO DO
// move file read to a function (pass the header, optional shorter length)
// ensure error checking
// convert to pure text fuctionality
// save to .asw and .txt files

#include <sys/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <libusb.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <syslog.h>

#define GDEBUG (0)
#define ASNEO_VID (0x081e)
#define ASNEO_HID_PID (0xbd04)
#define ASNEO_COMMS_PID (0xbd01)
#define ASCONFIG ("/home/pi/.config/alphadrive/alphadrive.conf")

// type representing an AlphaWord File Header
typedef struct AWFileHeads {
    char filename[16];
    char password[8];
    uint32_t filesize;
    uint32_t minsize;
    uint8_t fflags;
    uint16_t filespaceno;
    uint16_t checksum;    
} AWFileHead;

// type representing AlphaDrive Configuration Settings
typedef struct ADConfig {
	char storepath[100];
	char distrib[10][100];
	int versioning;
} ADConfig;

int getNeoComms(libusb_device_handle **handle);
int isAlphasmart(int vid, int pid, int coms);
void dumpbuf(unsigned char* ptr, int size, int chunk);
int talkAndListen(libusb_device_handle *handle, unsigned char* buffer, int send, int recv, int* actual);
int sendcmd(libusb_device_handle *handle, unsigned char* buffer, int send, int* actual, int timeout);
int receive(libusb_device_handle *handle, unsigned char* buffer, int recv, int* actual, int timeout);
AWFileHead makeHead(unsigned char* buffer);
int extractInt(unsigned char* buffer, int location, int span);
int insertInt(unsigned char* buffer, int location, int value, int span);
int findAlphie(libusb_context *context, int comms_mode, libusb_device_handle **handle, int *numConfigs);
int findAndFlip(libusb_context *context, libusb_device_handle **handle);
int restartNeo(libusb_device_handle *handle);
int getFileHeaders(libusb_device_handle *handle, AWFileHead **fileheaders, int *count);
int insertChecksum(unsigned char* buffer, int length);
int readAWFile(libusb_device_handle *handle, uint16_t app, uint8_t index, int size, unsigned char **filedata, int *received);
ADConfig getConfig();
char** indexTokens(char* string, char delim);
int download(libusb_device_handle *dohandle, int index, AWFileHead header, ADConfig config);
int dir(ADConfig config, char** dir);
int endsWith(char* source, char* match);
int switchMode(libusb_device_handle **handle);
int configCommsAlphie(libusb_context *context, libusb_device_handle **handle);


// main method
int main(int argc, char *argv[]){  
  int res;
  libusb_device_handle *handle;
  openlog("alphadrive", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

  if (argc > 1){
	  syslog(LOG_NOTICE, "HID add udev call");
    if (strcmp("switch", argv[1])==0){
      res = switchMode(&handle);
      syslog(LOG_NOTICE, "HID switched");
      return res;
    }
  }
	  syslog(LOG_NOTICE, "Comms add udev call");


  ADConfig config = getConfig();	
	
  res = getNeoComms(&handle);
  if (res<0) {
    printf("Error: Could not connect to Neo.\n");
    return(-1);
  }    
  
  // switch to ASM mode
  unsigned char asmode[] = { 0x01 };  
  unsigned char vers[] = {0, 0};  
  int got = 0;
  printf("Trying mode switch\n");
  res = libusb_bulk_transfer(handle, 0x01, asmode, 0x01, &got, 100);
  if (res != 0){
	  printf("Error switching mode!\n");
	}
	else {
	    res = libusb_bulk_transfer(handle, 0x82, vers, 0x02, &got, 100);
	}
	if (res != 0){
		printf("Error reading version\n");
	}
	else {
		int version = vers[0] << 8 | vers[1];
		printf("Alphasmart Version: %04x\n", version);
	}
	
	
  // reset
  unsigned char reset[] = {0x3f, 0xff, 0x00, 0x72, 0x65, 0x73, 0x65, 0x74}; //reset     
  printf("Trying reset\n");
  // dumpbuf(reset, 8, 8);
  res = libusb_bulk_transfer(handle, 0x01, reset, 0x08, &got, 0);

  // switch applet to Neo OS
  unsigned char switcho[] = {0x3f, 0x53, 0x77, 0x74, 0x63, 0x68, 0x00, 0x00}; //switch app          
  talkAndListen(handle, switcho, 8, 8, &got);
  if (GDEBUG) dumpbuf(switcho, got, 8);  
  
  int dirindex=0;  // look for open dir index
  AWFileHead *fileheaders = NULL; 
  int headcount = 0; 
  res = getFileHeaders(handle, &fileheaders, &headcount);
  if (res<0){
	  printf("Could not read file headers");
  }
  else {
	  int f=0;	  
	  while (f++<=headcount){
	    printf("%03u.  %-15s  %8u bytes  slot:0x%04x \n", f, fileheaders[f].filename, fileheaders[f].filesize, fileheaders[f].filespaceno);
	    if (((fileheaders[f].fflags & 0x02) != 0) && (strcmp(fileheaders[f].filename, "@drive")==0)) dirindex = f;
	  }
	  if (dirindex > 0) printf("Drive directory is open in index: 0x%02x slot: 0x%02x \n", dirindex, fileheaders[dirindex].filespaceno);  
  }
  
  // process @drive instructions if relevant
  // else do full backup
  
  if (dirindex==0){
	  int i;
	  for (i=1; i<headcount; i++){
		  download(handle, i, fileheaders[i], config);
      }
  }
  else {
    printf("Follow orders here\n");
    char** mydir = malloc(160000); 
    dir(config, mydir);
  } 
  
  // restartNeo(handle);
  syslog(LOG_NOTICE, "Comms udev call complete");
  return 1;
}     

// gets a directory of native files (trims names to Neo names)
int dir(ADConfig config, char** dir){
	DIR *dp;
	struct dirent *ep;
	dp = opendir(config.storepath);
	int j = 0;
	if (dp!=NULL){
		while (ep = readdir(dp)){
			if (ep->d_type != DT_REG) continue;
			if (!endsWith(ep->d_name, ".native")) continue;
		    printf("%s\n", ep->d_name);		    
		    dir[j] = ep->d_name;
		    dir[j][strlen(ep->d_name)-7]=0;
		    printf("  %s\n", dir[j]);
		    j++;
		}
        closedir(dp);
    }		
    else return -1;
    return 0;
}	
  
// downloads an AlphaWord file to local disk (native and unicode versions)  
int download(libusb_device_handle *handle, int index, AWFileHead header, ADConfig config){
      unsigned char *filedata;
      int received = 0;        
      printf("Downloading %s.txt (%d bytes)\n", header.filename, header.filesize);
      int res = readAWFile(handle, 0xa000, index, header.filesize, &filedata, &received);
      if (res<0) return res;
  
      // dumpbuf(filedata, received, 16);
      // printf("%s", filedata);
  
      // write native
      FILE *fp;
      char path[150];
      sprintf(path, "%s%s.native", config.storepath, header.filename);
      fp = fopen(path, "wb");
      fwrite(filedata, 1, received, fp);
      fclose(fp);  
      chmod(path, 0x1ff);
  
      char path2[150];
      sprintf(path2, "%s%s.txt", config.storepath, header.filename);
      fp = fopen(path2, "wb");
      fputc(0xff, fp);  // unicode BOM
      fputc(0xfe, fp);
      int j=0;
      for (j=0; j<received; j++){
        char c = filedata[j];
        if (c==0xa1) c = 0x20;      
        if (c==0x0d) {
	      fputc(0x0d, fp);
	      fputc(0x00, fp);
	      c = 0x0a;
	    }
	    if (c!=0xa7) {
		  fputc(c, fp);
		  fputc(0x00, fp);
	    }	  
      }  
      fclose(fp);
      chmod(path2, 0777);
      free(filedata);    
      printf("Done.\n");
      return 0;  
}

// reads the raw data from the specified file
int readAWFile(libusb_device_handle *handle, uint16_t app, uint8_t index, int size, unsigned char **filedata, int *received){
  // download file
  if (GDEBUG) printf("Expected size: %d bytes\n", size);
  unsigned char download[] = {0x1c, 0, 0, 0, 0, 0, 0, 0}; // read raw file command
  insertInt(download, 1, size, 3);   // set expected size
  insertInt(download, 4, index, 1);  // set file index
  insertInt(download, 5, app, 2);    // set applet
  insertChecksum(download, 8);       // calc/set checksum
  if (GDEBUG) dumpbuf(download, 8, 8);
  int got;
  talkAndListen(handle, download, 8, 8, &got);
  if (download[0]!=0x53){
      printf("Unexpected response: %02x\n", download[0]);
      return -1;
  }
  if (GDEBUG) dumpbuf(download, 8, 8);
  size = extractInt(download, 1, 4);    // get reported size
  if (GDEBUG) printf("Neo reports size: %d bytes\n", size); 
  unsigned char* _filedata = malloc(size);    // set up data receive array
  unsigned char* ptr = _filedata;             // point to start
  int total = 0;
  while (total<size){
    unsigned char blockread[] = {0x10, 0, 0, 0, 0, 0, 0, 0x10};  // block read command
    talkAndListen(handle, blockread, 8, 8, &got);
    if (blockread[0]!=0x4d){
      printf("Unexpected response: %02x\n", blockread[0]);
      return -1;
    }
    int blockSize = extractInt(blockread, 1, 4);
    int checkSum = extractInt(blockread, 5, 2);
    if (GDEBUG) printf("Blocksize: %d bytes, checksum: %04x\n", blockSize, checkSum);  
    if (blockSize==0){
      if (total<size){
        printf("No more data from Neo. Got %d of %d expected bytes\n", total, size);
        return -1;
      }
      break;
    }
    int res = receive(handle, ptr, blockSize, &got, 0);
    if (res<0){
      printf("IO error.\n");
      return -1;
    }
    if (got!=blockSize){
		  printf("Data transfer error\n");  // replace with a "keep reading till done" approach
		return -1;
	  }		
    int cs = 0;
    int i;
    for (i=0; i<got; i++){
      cs = (cs + ptr[i]) & 0xffff;
    }
	  if (GDEBUG) printf("Calc checksum: %04x\n", cs);
	  if (cs!=checkSum){
	    printf("Data validation error: checksum mismatch\n");
	    return -1;
	  }
    if (GDEBUG) printf("Read: %d bytes\n", got);
    ptr += got;
    total += got;
  }
  if (GDEBUG) printf("File read complete: %d bytes\n", total);  
  printf("done");
  *filedata = _filedata;
  *received = total;
  return 0;
}

// get file headers for Alphaword (applet 0xa000)
int getFileHeaders(libusb_device_handle *handle, AWFileHead **fileheaders, int *count){
    int f = 1;  // file numbering starts from 1
  AWFileHead *heads = malloc(255*sizeof(AWFileHead));
  for (f=1; f<256; f++){
    unsigned char filereq[] = {0x13, 0, 0, 0, f, 0xa0, 0x00, 0};
    insertChecksum(filereq, 8);
    int got = 0;
    int res = talkAndListen(handle, filereq, 8, 8, &got);
    if (got==8){
        if (filereq[0]!=0x5a) {
			if (filereq[0]==0x90){
				printf("no more files\n");				
			}
			else if (filereq[0]==0x8f){
				printf("Checksum error");
				*fileheaders = NULL;
				return -1;
			}	
			else {
		        printf("Unexpected response\n");
		        *fileheaders = NULL;
		        return -1;
		    }
		    break;
		}
		else {
		    int len = filereq[1] << 24 | filereq[2] << 16 | filereq[3] << 8 | filereq[4];  // get file length
		    unsigned char *buf;
		    buf = malloc(len);
		    res = receive(handle, buf, len, &got, 200);
		    if (res == 0) {
				heads[f] = makeHead(buf);				
//  printf("%03u.  %-15s  %8u bytes  slot:0x%04x  CHK:0x%04x  PW:%-7s  Flags:0x%01x\n", f, heads[f].filename, heads[f].filesize, heads[f].filespaceno, heads[f].checksum, heads[f].password, heads[f].fflags);				
			}
		}
    }
    else {
		printf("No more files\n");
		break;
    }			
  }
  *fileheaders = heads;
  *count = f;
  return 0;
}

// restart Neo in HID mode
int restartNeo(libusb_device_handle *handle){
  printf("Restarting Neo");
  unsigned char restart[] = {0x08, 0, 0, 0, 0, 0, 0, 0x08};
  int got;
  int res = talkAndListen(handle, restart, 8, 8, &got);
  if (res<0 || got!=8) {
    printf("Error restarting Neo\n");
    return -1;
  }
  else {
    if (restart[0]!=0x52){
      printf("Unexpected response\n");
      return -1;
    }
  }         
  return 0;
}

void dumpbuf(unsigned char* bptr, int size, int chunk){
	int off = 0;
	int i = 0;
	for (off=0; off<size; off+=chunk){
        for (i=0; i<chunk; i++){
			if (off+i >= size) break;
	        printf("%02x ", (int)bptr[off+i]);	  
        }
        printf("    ");
        for (i=0; i<chunk; i++){
            if (off+i >= size) break;
            char c = bptr[off+i];
            if (c<0x20 || c>0x7e) printf(" ");
            else printf("%c", c);
        }
        printf("\n");  
	}       
}


// returns true if device vid and pid matches alphasmartin HID or Comms mode
int isAlphasmart(int vid, int pid, int coms){        
    if (vid!=ASNEO_VID){ 
        return -1;
    }
    int pidmatch = (coms==0)? ASNEO_HID_PID : ASNEO_COMMS_PID;
    char *mode = ((coms==0)? "HID" : "Comms");
    if (pid!=pidmatch) {
        return -1;
    } 
    printf("\nDetected Alphasmart Neo in %s mode\n", mode); 
    return 1;
}

// send Neo command and receive response
int talkAndListen(libusb_device_handle *handle, unsigned char* buffer, int send, int recv, int* actual){
    int res = 0;
    res = sendcmd(handle, buffer, send, actual, 200);
    if (res < 0) return -1;
    res = receive(handle, buffer, recv, actual, 200);
    if (res < 0) return -2;
    return 0;
}

// send Neo command
int sendcmd(libusb_device_handle *handle, unsigned char* buffer, int send, int* actual, int timeout){
    if (GDEBUG) dumpbuf(buffer, send, 8);
    int res = 0;
    int sent = 0;
    res = libusb_bulk_transfer(handle, 0x01, buffer, send, &sent, timeout);
    if (res<0 || sent!=send) {
		printf("Could not send command\n");
        if (res<0) printf(libusb_error_name(res));
		return -1;
    }		
    return 0;
}

// receive Neo response
int receive(libusb_device_handle *handle, unsigned char* buffer, int recv, int* actual, int timeout){
    int res = 0;
    res = libusb_bulk_transfer(handle, 0x82, buffer, recv, actual, timeout);
    if (res<0) {
		printf(libusb_error_name(res)); 
		return -1;
	}    
	int got = *actual;
    while (got<recv) {
		if (GDEBUG) printf("Got %d of %d.\n", got, recv);
		int expect = recv - got;
        res = libusb_bulk_transfer(handle, 0x82, buffer+(got*sizeof(unsigned char)), expect, actual, timeout);
        if (res<0) {
		    printf(libusb_error_name(res)); 
		    return -1;
	    }    
		got += *actual;
    }		
    *actual = got;
    if (GDEBUG) dumpbuf(buffer, recv, 8);
    return 0;
}

/* Extracts a n-byte integer (MSB-first format) from an unsigned char buffer
*/
int extractInt(unsigned char* buffer, int location, int span){
    int val = 0;
    while (span > 0){
		val = val << 8;		
		val += buffer[location++] & 0xff;		
		span--;
	}	
	return val;
}

/* Inserts a n-byte integer (MSB-first format) into an unsigned char buffer
*/
int insertInt(unsigned char* buffer, int location, int value, int span){
    int index = location+span;
    while (--index >= location){
		buffer[index] = value & 0xff;
		value = value >> 8;						
	}	
	return 0;
}

/* Inserts a checksum (sum mod 0xff) in the last byte of the buffer
 * */
int insertChecksum(unsigned char* buffer, int length){
    int i=0;
    unsigned char check = 0;
    while (i<length-1){
		check = (check + buffer[i++]) & 0xff;
    }	
    buffer[i]=check;
    return 0;
}

/* Makes a AWFileHead struct from raw Neo data in the buffer
*/
AWFileHead makeHead(unsigned char* buffer){
	AWFileHead head; 
	strncpy(head.filename, (char*)buffer, 16);  // copy filename
	strncpy(head.password, (char*)(buffer+16), 8);	// copy password
	head.minsize = extractInt(buffer, 24, 4);  // get file min size
	head.filesize = extractInt(buffer, 28, 4);  // get file actual size
	head.fflags = extractInt(buffer, 35, 1);  // get flags
	head.filespaceno = extractInt(buffer, 36, 2);	 // get the filespace number (identifies the 8 default files)
	head.checksum = extractInt(buffer, 38, 2);  // get the checksum
	return head;
}

// finds a HID alphasmart and flips to comms mode
int switchMode(libusb_device_handle **handle){
  struct libusb_context *cont = NULL;
  int res;
  res = libusb_init(&cont);  // initialise libusb
  if (res<0){
	  printf("ERROR: could not get USB context\n");
	  return(res);
  }
  int numconf;  
  findAndFlip(cont, handle);
  return 0;
}

/* Gets a connected Neo in Comms mode
   If necessary, detects HID-mode Neo and flips it to Comms mode
*/
int getNeoComms(libusb_device_handle **handle){
  struct libusb_context *cont = NULL;
  int res;
  res = libusb_init(&cont);  // initialise libusb
  if (res<0){
	  printf("ERROR: could not get USB context\n");
	  return(res);
  }
  int deblevel = (GDEBUG)? 3 : 0;	  
  libusb_set_debug(cont, deblevel);  // set debug level  
  res = configCommsAlphie(cont, handle);
  if (res < 0){
    return res;
  }
  int numConfigs = 0;
  res = findAlphie(cont, 1, handle, &numConfigs);
  if (res < 0){
	  return res;
  }
  return 0;
}  
  
/* Finds a connected Alphasmart Neo, in either HID or comms mode depending on param 2.
*/
int findAlphie(libusb_context *context, int comms_mode, libusb_device_handle **handle, int *numConfigs){
  struct libusb_device **list;
  struct libusb_device *found;
  found = NULL;
  struct libusb_device_descriptor info;  
  // get USB devices  
  int res = libusb_get_device_list(context, &list);
  ssize_t i = 0;
  if (res < 0){
    printf("ERROR: could not list USB devices\n");
    return(res);
  }
  // search for Neo device
  for (i = 0; i < res; i++) {
    libusb_device *device = list[i];
    libusb_get_device_descriptor(list[i], &info);  // get device info    
    if (isAlphasmart(info.idVendor, info.idProduct, comms_mode)>0) {
        printf("VID=%04x PID=%04x\n", info.idVendor, info.idProduct); 
        found = device;
        *numConfigs = info.bNumConfigurations;
        break;
    }
  }
  if (numConfigs==0){
    printf("Could not configure Neo\n");
    return -1;
  }
  if (!found) return -1;

  int devadd = libusb_get_device_address(found);
  printf("Device address: %04x\n", devadd);
	// open handle and initialise for comms  
  res = libusb_open(found, handle);
  if (res){
	    if (res==LIBUSB_ERROR_ACCESS) printf("Access Denied - try using sudo\n");               
      printf("error! %d \n", res);    
  }
  if (res<0) printf("Error line %d: %d : %s\n", __LINE__, res, libusb_error_name(res));
  int bconf;
  res = libusb_get_configuration(*handle, &bconf);
  printf("Config: %02x\n", bconf);
  libusb_set_configuration(*handle, bconf);
  
  if (libusb_kernel_driver_active(*handle, 0)){
      res = libusb_detach_kernel_driver(*handle, 0);    
  }  
  res = libusb_claim_interface(*handle, 0);      
  if (res<0) printf("Error line %d: %d : %s\n", __LINE__, res, libusb_error_name(res));
  
  libusb_free_device_list(list, 1); 
  return 0;
}

/* Searches for a Neo in HID mode. If found, sends magic sequence to flip to Comms mode.
   Detects new Comms device and returns it.
*/
int findAndFlip(libusb_context *context, libusb_device_handle **handle){	
  int numConfigs;
  int res = findAlphie(context, 0, handle, &numConfigs);
  if (res!=0){
      printf("ERROR: could not connect to Neo.\n");
      return -1;
  }
  if (numConfigs==0){
	    printf("Error: could not configure Neo\n");
	    return -1;
  }  

  // attempt flip to comms mode
  printf("\nSwitching to comms mode.");
  unsigned char magic[] = {0x6, 0x1, 0x2, 0x4, 0x3, 0x7};  
  unsigned char dat;
  int i;
  for (i = 0; i < 6; i++){
	  dat = magic[i]; 
    res = libusb_control_transfer(*handle, 0x21, 0x09, ((0x02 << 8) | 0), 0, &dat, 1, 200);
    if (res < 0) {
		  printf("Error: %d : %s", res, libusb_error_name(res));
		  return res;
	  }
  }
  printf("Releasing\n");
  // release HID device  
  libusb_release_interface(*handle, 0);
  libusb_close(*handle);
	
  printf("Waiting for Neo");
		
  return 0;  
}

int configCommsAlphie(libusb_context *context, libusb_device_handle **handle){
  // now poll for Comms mode device  
  *handle = NULL;
  int timo = 0;
  int trylim = 50;
  int numConfigs;
  while (timo++ < trylim){  
	  printf(".");
    int res = findAlphie(context, 1, handle, &numConfigs);
    if (res==0 && numConfigs>0){		
      break;
    }
    if (numConfigs==0){
      printf("Could not configure Neo\n");
    }    
    usleep(200000);		
  }
  printf("\n");
  if (*handle==NULL){
    printf("Neo not found after %d attempts.\n", trylim);
    return -1;
  }
  
  // initialise comms mode Neo
  libusb_device *device = libusb_get_device(*handle);
  int res;
  
  printf("Set device address\n");  // is this causing the retrigger?
  unsigned char ans[] = {0, 0, 0, 0, 0, 0, 0, 0};    
  res = libusb_control_transfer(*handle, 0x80, 0, 0, 0, ans, 2, 200);
  if (res < 0) {
		printf("\n %s", libusb_error_name(res));
		printf("Could not send query message\n");
		return -1;
	}    
	res = libusb_control_transfer(*handle, 0, 0, 0, 0, ans, 2, 200);    
	if (res < 0) {
		  printf("\n %s", libusb_error_name(res));
		  printf("Could not get response\n");
		  return -1;
	}    
	printf("Response: %02x %02x\n", ans[0], ans[1]); 
	    
	int bconf;
  res = libusb_get_configuration(*handle, &bconf);
  if (res!=0) {
    printf("Could not configure Neo\n");
    return -1;
  }
  struct libusb_config_descriptor *dconfig = NULL;
  res = libusb_get_active_config_descriptor(device, &dconfig);
  if (res!=0) {
      printf("Could not configure Neo\n");
      return -1;
  }
  printf("Interfaces: %d\n", dconfig->bNumInterfaces);
  struct libusb_interface ifo = dconfig->interface[0];
  int alts = ifo.num_altsetting;
  int i;
  for (i=0; i<alts; i++){
    struct libusb_interface_descriptor lid = ifo.altsetting[i];
    int j=0;
	  for (j=0; j<lid.bNumEndpoints; j++){
		  struct libusb_endpoint_descriptor led = lid.endpoint[j];
	    uint8_t addr = led.bEndpointAddress;
	    printf("Interface alt: %02x, Endpoint: %02x, EP Addr: %02x \n", i, j, addr);
	  }	  
	}   
  printf("Config value: %02x \n", bconf);
  printf("Setting config\n");
  libusb_set_configuration(*handle, 0);  
  return 0;
}


// gets the config file data
ADConfig getConfig(){
	ADConfig config;
    FILE *fp;
    fp = fopen(ASCONFIG, "r");
    char* fcontent = malloc(2002);
    fgets(fcontent, 2000, fp);    
    while (fcontent!=NULL){	
	  if (fcontent[0]=='#') {
		  if (fgets(fcontent, 2000, fp)==NULL) break;
		  continue;	
	  }	        
      int i = strlen(fcontent);
      while (isspace(fcontent[--i])) fcontent[i]=0;  // trim
      while (strlen(fcontent)>0 && isspace(fcontent[0])) fcontent = &(fcontent[1]);        
      
	  char** keyval = indexTokens(fcontent, '=');	  
	  if (strcmp(keyval[0], "store")==0) {
		  int j = strlen(keyval[1]);
		  memcpy(&config.storepath, keyval[1], j+1);		
	  }
	  if (strcmp(keyval[0], "distrib")==0) {		  
		  char** tokens = indexTokens(keyval[1], ',');
		  i=0;
		  while (tokens[i]!=NULL && i<10){
			  int j = strlen(tokens[i]);
			  memcpy(&config.distrib[i], tokens[i], j+1);
			  i++;
	      }		  
	  }	
	  if (strcmp(keyval[0], "versioning")==0){
	      int c = strcmp(keyval[1], "on");
	      int v = (c==0)? 1 : 0;
	      config.versioning = v;
	  }  
	  if (fgets(fcontent, 2000, fp)==NULL) break;
    }
    fclose(fp);
    printf("Store: %s\n", config.storepath);
    printf("Versioning: %d\n", config.versioning);
    printf("First distrib: %s\n", config.distrib[0]);
    return config;
}	    


// splits a string by delimiter into a null-terminated array of substrings
char** indexTokens(char* string, char delim){
  if (delim==0) return NULL;  // cannot have string terminator as delimiter!
  int len = strlen(string)+1;  // char buffer length
  char** buf = malloc(len*sizeof(string));  // create pointer buffer
  int i=0;   // string index
  int pi=0;  // pointers index
  buf[0] = (void*)0;
  // find delimeters and store their offset positions in the string
  for (i=0; i<len; i++){     // loop through chars in string  
    if (string[i]==delim){   // if delimiter found
      buf[++pi] = (void*)(i+1);       // index of next substring      
    }
  }
  buf[++pi] = NULL;  // flag: end of pointers
  ++pi;
  buf = realloc(buf, (pi*sizeof(&string))+len);  // expand buffer to accommodate substrings
  uint si = (uint)&(buf[pi]);  // get string insertion point
  memcpy((void*)si, string, len);  // copy string into buffer
  buf[0] = (char*)si;  // convert offset to pointer (point to start of substrings)
  pi=0;
  while (buf[++pi]!=NULL){
    buf[pi] = (char*)((uint)buf[pi]+si);     // convert offset to pointer
    *(char*)((uint)buf[pi]-1) = 0;  // insert terminator before substring (replacing delimeter)
  }
  return (char**) buf;
}

// returns true if the string ends with the match
int endsWith(char* source, char* match){    
    int inset = strlen(source)-strlen(match);
    if (inset < 0) return 0;
    char* sub = &(source[inset]);
    if (strcmp(sub, match)==0) return 1;
    return 0;
}	
