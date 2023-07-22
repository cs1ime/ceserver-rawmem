
#include "ceserver.h"
#include "ceserver_interface.h"
#include <cxxopts.hpp>
#include <dirent.h>
#include <fcntl.h>
#include <iostream>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <set>
#include <stdarg.h>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <thread>
#include <unistd.h>
#include <zlib.h>

#ifdef __linux__
#define QEMUKVM_ENABLE
#endif

#ifdef QEMUKVM_ENABLE
#include "qemukvm/qemukvm2dma.h"
#endif

#include "rawmemfile/rawmem2dma.h"

#define CESERVERVERSION 5
char versionstring[] = "CHEATENGINE Network 2.2";

volatile int done;
std::set<std::thread *> thread_pool;

int debug_log(const char *format, ...) {
  va_list list;
  va_start(list, format);
  int ret = vprintf(format, list);
  va_end(list);

#ifdef __ANDROID__
  va_start(list, format);
  LOGD(format, list);
  va_end(list);
#endif

  return ret;
}

ssize_t recvall(int s, void *buf, size_t size, int flags) {
  ssize_t totalreceived = 0;
  ssize_t sizeleft = size;
  unsigned char *buffer = (unsigned char *)buf;

  // enter recvall
  flags = flags | MSG_WAITALL;

  while (sizeleft > 0) {
    ssize_t i = recv(s, &buffer[totalreceived], sizeleft, flags);

    if (i == 0) {
      debug_log("Error: recv returned 0\n");
      return i;
    }

    if (i == -1) {
      debug_log("recv returned -1\n");
      if (errno == EINTR) {
        debug_log("errno = EINTR\n");
        i = 0;
      } else {
        debug_log("Error during recvall: %d. errno=%d\n", (int)i, errno);
        return i; // read error, or disconnected
      }
    }

    totalreceived += i;
    sizeleft -= i;
  }

  // leave recvall
  return totalreceived;
}
ssize_t sendall(int s, void *buf, size_t size, int flags) {
  ssize_t totalsent = 0;
  ssize_t sizeleft = size;
  unsigned char *buffer = (unsigned char *)buf;

  while (sizeleft > 0) {
    ssize_t i = send(s, &buffer[totalsent], sizeleft, flags);

    if (i == 0) {
      return i;
    }

    if (i == -1) {
      if (errno == EINTR)
        i = 0;
      else {
        debug_log("Error during sendall: %d. error=%s\n", (int)i,
                  strerror(errno));
        return i;
      }
    }

    totalsent += i;
    sizeleft -= i;
  }

  return totalsent;
}

class datasender {
public:
  datasender(int fd) { m_fd = fd; }
  void push_data(void *buffer, size_t sz) {
    for (size_t i = 0; i < sz; i++) {
      m_data.push_back(((uint8_t *)buffer)[i]);
    }
  }
  void send(int flags) {
    if (m_data.size() > 0) {
      sendall(m_fd, m_data.data(), m_data.size(), flags);
      m_data.clear();
    }
  }

private:
  int m_fd;
  std::vector<uint8_t> m_data;
};

ssize_t sendstring16(int s, char *str, int flags) {
  uint16_t l;
  if (str)
    l = strlen(str);
  else
    l = 0;
  datasender alldata(s);
  alldata.push_data(&l, sizeof(l));
  if (l)
    alldata.push_data(str, l);
  alldata.send(flags);

  return l;
}
int sendinteger(int s, int val, int flags) {
  return sendall(s, &val, sizeof(val), flags);
}
char *receivestring16(int s) {
  char *str;
  uint16_t l;
  recvall(s, &l, sizeof(l), 0);

  if (l) {
    str = (char *)malloc(l + 1);
    recvall(s, str, l, 0);
    str[l] = 0;
    return str;
  } else
    return NULL;
}

#include <chrono>

int DispatchCommand(int currentsocket, unsigned char command){
	//std::cout<<"nfd="<<std::to_string(currentsocket)<<"cmd="<<std::to_string(command)<<std::endl;

	switch (command)
  	{
    	case CMD_GETVERSION:
    	{
      		PCeVersion v;
      		//debug_log("version request");
      		fflush(stdout);
      		int versionsize=strlen(versionstring);
      		v=(PCeVersion)malloc(sizeof(CeVersion)+versionsize);
      		v->stringsize=versionsize;
      		v->version=2;
      		memcpy((char *)v+sizeof(CeVersion), versionstring, versionsize);
      		//version request
      		sendall(currentsocket, v, sizeof(CeVersion)+versionsize, 0);

      		free(v);

      		break;
    	}
		case CMD_TERMINATESERVER:
    	{
    	  	debug_log("Command to terminate the server received\n");
    	  	fflush(stdout);
    	  	close(currentsocket);
    	  	exit(0);
			break;
    	}
		case CMD_CLOSECONNECTION:
    	{
    		debug_log("Connection %d closed properly\n", currentsocket);
    		fflush(stdout);
    		close(currentsocket);
    	  	return 0;
    	}
		case CMD_CREATETOOLHELP32SNAPSHOT:
		{
			CeCreateToolhelp32Snapshot params;
			//debug_log("CMD_CREATETOOLHELP32SNAPSHOTEX\n");

			if (recvall(currentsocket, &params, sizeof(CeCreateToolhelp32Snapshot), MSG_WAITALL) > 0)
			{
				HANDLE r = ceserver::CreateToolhelp32Snapshot(params.dwFlags, params.th32ProcessID);
				sendall(currentsocket, &r, sizeof(HANDLE), 0);
			}
			break;
		}
		case CMD_PROCESS32FIRST: //obsolete
    	case CMD_PROCESS32NEXT:
    	{
    	  	HANDLE toolhelpsnapshot;
			BOOL result;
			CeProcessEntry *r;
        	int size;
			process_list_entry pe={};
    	  	if (recvall(currentsocket, &toolhelpsnapshot, sizeof(toolhelpsnapshot), MSG_WAITALL) >0)
    	  	{
				
				if(command == CMD_PROCESS32FIRST)
					result=ceserver::Process32First(toolhelpsnapshot,&pe);
				else
					result=ceserver::Process32Next(toolhelpsnapshot, &pe);

		  	}
			if (result && pe.name.length() > 0)
        	{
        	  size=sizeof(CeProcessEntry)+ pe.name.length();
        	  r=(PCeProcessEntry)malloc(size);
        	  r->processnamesize=pe.name.length();
        	  r->pid=pe.pid;
        	  memcpy((char *)r+sizeof(CeProcessEntry), pe.name.c_str(), r->processnamesize);
        	}
        	else
        	{
        	  size=sizeof(CeProcessEntry);
        	  r=(PCeProcessEntry)malloc(size);
        	  r->processnamesize=0;
        	  r->pid=0;
        	}
			r->result=result;
        	sendall(currentsocket, r, size, 0);
        	free(r);
			break;
		}
		case CMD_MODULE32FIRST: //slightly obsolete now
    	case CMD_MODULE32NEXT:
    	{
			HANDLE toolhelpsnapshot;
      		if (recvall(currentsocket, &toolhelpsnapshot, sizeof(toolhelpsnapshot), MSG_WAITALL) >0)
      		{
      		  	BOOL result;
      		  	module_list_entry me;
      		  	CeModuleEntry *r;
      		  	int size;

      		  	if (command==CMD_MODULE32FIRST)
      		  	  result=ceserver::Module32First(toolhelpsnapshot, &me);
      		  	else
      		  	  result=ceserver::Module32Next(toolhelpsnapshot, &me);

      		  	if (result)
      		  	{
      		    size=sizeof(CeModuleEntry)+ me.moduleName.length();
      		    r=(PCeModuleEntry)malloc(size);
    		      r->modulebase=me.baseAddress;
    		      r->modulesize=me.moduleSize;
    		      r->modulenamesize=me.moduleName.length();
    		      r->modulepart=me.part;


    		      // Sending %s size %x\n, me.moduleName, r->modulesize
    		      memcpy((char *)r+sizeof(CeModuleEntry), me.moduleName.c_str(), r->modulenamesize);
    		    }
    		    else
    		    {
    		      size=sizeof(CeModuleEntry);
    		      r=(PCeModuleEntry)malloc(size);
    		      r->modulebase=0;
    		      r->modulesize=0;
    		      r->modulenamesize=0;
    		      r->modulepart=0;
    		    }

    		    r->result=result;
    		    sendall(currentsocket, r, size, 0);

    		    free(r);
    		  }

			break;
		}
		case CMD_CLOSEHANDLE:
		{
			HANDLE h;

      		if (recvall(currentsocket, &h, sizeof(h), MSG_WAITALL)>0)
      		{
      		  ceserver::CloseHandle(h);
      		  int r=1;
      		  sendall(currentsocket, &r, sizeof(r), 0); //stupid naggle

      		}
      		else
      		{
      		  debug_log("Error during read for CMD_CLOSEHANDLE\n");
      		  close(currentsocket);
      		  fflush(stdout);
      		  return 0;
      		}
      		break;
		}
		case CMD_READPROCESSMEMORY:
		{
			CeReadProcessMemoryInput c;

      		int r=recvall(currentsocket, &c, sizeof(c), MSG_WAITALL);
      		if (r>0)
      		{
      		  PCeReadProcessMemoryOutput o=NULL;
      		  o=(PCeReadProcessMemoryOutput)malloc(sizeof(CeReadProcessMemoryOutput)+c.size);

      		  o->read=ceserver::ReadProcessMemory(c.handle, (uintptr_t)c.address, &o[1], c.size);

      		  if (c.compress)
      		  {
      		    //compress the output
#define COMPRESS_BLOCKSIZE (64*1024)
          		int i;
          		unsigned char *uncompressed=(unsigned char *)&o[1];
          		uint32_t uncompressedSize=o->read;
          		uint32_t compressedSize=0;
          		int maxBlocks=1+(c.size / COMPRESS_BLOCKSIZE);

          		unsigned char **compressedBlocks=(decltype(compressedBlocks))malloc(maxBlocks*sizeof(unsigned char *) ); //send in blocks of 64kb and reallocate the pointerblock if there's not enough space
          		int currentBlock=0;

          		z_stream strm;
          		strm.zalloc = Z_NULL;
          		strm.zfree = Z_NULL;
          		strm.opaque = Z_NULL;
          		deflateInit(&strm, c.compress);

          		compressedBlocks[currentBlock]=(unsigned char*)malloc(COMPRESS_BLOCKSIZE);
          		strm.avail_out=COMPRESS_BLOCKSIZE;
          		strm.next_out=compressedBlocks[currentBlock];

          		strm.next_in=uncompressed;
          		strm.avail_in=uncompressedSize;

          		while (strm.avail_in)
          		{
          		  r=deflate(&strm, Z_NO_FLUSH);
          		  if (r!=Z_OK)
          		  {
          		    if (r==Z_STREAM_END)
          		      break;
          		    else
          		    {
          		      debug_log("Error while compressing\n");
          		      break;
          		    }
          		  }

          		  if (strm.avail_out==0)
          		  {
          		    //new output block
          		    currentBlock++;
          		    if (currentBlock>=maxBlocks)
          		    {
          		      //list was too short, reallocate
          		      debug_log("Need to realloc the pointerlist (p1)\n");

          		      maxBlocks*=2;
          		      compressedBlocks=(decltype(compressedBlocks))realloc(compressedBlocks, maxBlocks*sizeof(unsigned char*));
          		    }
          		    compressedBlocks[currentBlock]=(unsigned char*)malloc(COMPRESS_BLOCKSIZE);
          		    strm.avail_out=COMPRESS_BLOCKSIZE;
          		    strm.next_out=compressedBlocks[currentBlock];
          		  }
          		}
          		// finishing compressiong
          		while (1)
          		{
				
          		  r=deflate(&strm, Z_FINISH);

          		  if (r==Z_STREAM_END)
          		    break; //done

          		  if (r!=Z_OK)
          		  {
          		    debug_log("Failure while finishing compression:%d\n", r);
          		    break;
          		  }

          		  if (strm.avail_out==0)
          		  {
          		    //new output block
          		    currentBlock++;
          		    if (currentBlock>=maxBlocks)
          		    {
          		      //list was too short, reallocate
          		      debug_log("Need to realloc the pointerlist (p2)\n");
          		      maxBlocks*=2;
          		      compressedBlocks=(decltype(compressedBlocks))realloc(compressedBlocks, maxBlocks*sizeof(unsigned char*));
          		    }
          		    compressedBlocks[currentBlock]=(unsigned char*)malloc(COMPRESS_BLOCKSIZE);
          		    strm.avail_out=COMPRESS_BLOCKSIZE;
          		    strm.next_out=compressedBlocks[currentBlock];
          		  }
          		}
      		    deflateEnd(&strm);

      		    compressedSize=strm.total_out;
      		    // Sending compressed data
              datasender sender(currentsocket);
              sender.push_data(&uncompressedSize, sizeof(uncompressedSize));
              sender.push_data(&compressedSize, sizeof(compressedSize));
      		    //sendall(currentsocket, &uncompressedSize, sizeof(uncompressedSize), MSG_MORE); //followed by the compressed size
      		    //sendall(currentsocket, &compressedSize, sizeof(compressedSize), MSG_MORE); //the compressed data follows
      		    for (i=0; i<=currentBlock; i++)
      		    {
      		      if (i!=currentBlock){
                  sender.push_data(compressedBlocks[i], COMPRESS_BLOCKSIZE);
                  //sendall(currentsocket, compressedBlocks[i], COMPRESS_BLOCKSIZE, MSG_MORE);
                }
      		      else
                {
                  sender.push_data(compressedBlocks[i], COMPRESS_BLOCKSIZE-strm.avail_out);
                  sender.send(0);
                  //sendall(currentsocket, compressedBlocks[i], COMPRESS_BLOCKSIZE-strm.avail_out, 0); //last one, flush
                }
      		        

      		      free(compressedBlocks[i]);
      		    }
      		    free(compressedBlocks);
      		  }
      		  else
      		    sendall(currentsocket, o, sizeof(CeReadProcessMemoryOutput)+o->read, 0);

      		  if (o)
      		    free(o);
      		}
      		break;
		}
		case CMD_WRITEPROCESSMEMORY:
    	{
    	  	CeWriteProcessMemoryInput c;

    	  	debug_log("CMD_WRITEPROCESSMEMORY:\n");

    	  	int r=recvall(currentsocket, &c, sizeof(c), MSG_WAITALL);
    	  	if (r>0)
    	  	{
    	  	  CeWriteProcessMemoryOutput o;
    	  	  unsigned char *buf;

    	  	  debug_log("recv returned %d bytes\n", r);
    	  	  debug_log("c.size=%d\n", c.size);

    	  	  if (c.size)
    	  	  {
    	  	    buf=(unsigned char *)malloc(c.size);

    	  	    r=recvall(currentsocket, buf, c.size, MSG_WAITALL);
    	  	    if (r>0)
    	  	    {
    	  	      debug_log("received %d bytes for the buffer. Wanted %d\n", r, c.size);
    	  	      o.written=ceserver::WriteProcessMemory(c.handle, (uintptr_t)c.address, buf, c.size);

    	  	      r=sendall(currentsocket, &o, sizeof(CeWriteProcessMemoryOutput), 0);
    	  	      debug_log("wpm: returned %d bytes to caller\n", r);

    	  	    }
    	  	    else
    	  	      debug_log("wpm recv error while reading the data\n");

    	  	    free(buf);
    	  	  }
    	  	  else
    	  	  {
    	  	    debug_log("wpm with a size of 0 bytes");
    	  	    o.written=0;
    	  	    r=sendall(currentsocket, &o, sizeof(CeWriteProcessMemoryOutput), 0);
    	  	    debug_log("wpm: returned %d bytes to caller\n", r);
    	  	  }
    	  	}
    	  	else
    	  	{
    	  	  debug_log("RPM: recv failed\n");
    	  	}
    	  	break;
    	}
		case CMD_GETREGIONINFO:
    	case CMD_VIRTUALQUERYEX:
    	{
			auto start=std::chrono::steady_clock::now();

    	  	CeVirtualQueryExInput c;
    	  	int r=recvall(currentsocket, &c, sizeof(c), MSG_WAITALL);
    	  	if (r>0)
    	  	{
    	  	  region_info rinfo;
    	  	  CeVirtualQueryExOutput o;

    	  	  if (sizeof(uintptr_t)==4)
    	  	  {
    	  	    if (c.baseaddress>0xFFFFFFFF)
    	  	    {
    	  	      o.result=0;
    	  	      sendall(currentsocket, &o, sizeof(o), 0);
    	  	      break;
    	  	    }
    	  	  }

    	  	  char mapsline[200];

    	  	  if (command==CMD_VIRTUALQUERYEX)
    	  	    o.result=ceserver::VirtualQueryEx(c.handle, (uintptr_t)c.baseaddress, &rinfo, NULL);
    	  	  else
    	  	  if (command==CMD_GETREGIONINFO)
    	  	    o.result=ceserver::VirtualQueryEx(c.handle, (uintptr_t)c.baseaddress, &rinfo, mapsline);
				//printf("c.baseaddress:%llX\r\n",c.baseaddress);
    	  	  o.protection=rinfo.protection;
    	  	  o.baseaddress=rinfo.baseaddress;
    	  	  o.type=rinfo.type;
    	  	  o.size=rinfo.size;

    	  	  if (command==CMD_VIRTUALQUERYEX)
    	  	    sendall(currentsocket, &o, sizeof(o), 0);
    	  	  else
    	  	  if (command==CMD_GETREGIONINFO)
    	  	  {
              datasender sender(currentsocket);
              sender.push_data(&o,sizeof(o));
    	  	    //sendall(currentsocket, &o, sizeof(o), MSG_MORE);
    	  	    {
    	  	      uint8_t size=strlen(mapsline);
                sender.push_data(&size, sizeof(size));
    	  	      //sendall(currentsocket, &size, sizeof(size), MSG_MORE);
    	  	      //sendall(currentsocket, mapsline, size, 0);
                sender.push_data(mapsline,size);
                sender.send(0);
    	  	    }
    	  	  }
    	  	}
			auto end=std::chrono::steady_clock::now();
			std::chrono::duration<double> dur=(end-start);
			//std::cout<<"through="<<dur.count()<<std::endl;
    	  	break;
    	}
		case CMD_VIRTUALQUERYEXFULL:
    	{
    	  	CeVirtualQueryExFullInput c;

    	  	int r=recvall(currentsocket, &c, sizeof(c), MSG_WAITALL);
    	  	if (r>0)
    	  	{
				auto r=ceserver::VirtualQueryExFull(c.handle,c.flags);
				uint32_t count=r->size();
				sendall(currentsocket, &count, sizeof(count),0);
				for(auto p : *r)
				{
					sendall(currentsocket, &p, sizeof(region_info),0);
					std::cout<<"address:"<< p.baseaddress<<std::endl;
				}
    	  	}
    	  	break;
    	}
		case CMD_OPENPROCESS:
		{
			int pid=0;

      		int r=recvall(currentsocket, &pid, sizeof(int), MSG_WAITALL);
      		if (r>0)
      		{
      		  	int processhandle;

      		  	debug_log("OpenProcess(%d)\n", pid);
      		  	processhandle=ceserver::OpenProcess(pid);

      		  	debug_log("processhandle=%d\n", processhandle);
      		  	sendall(currentsocket, &processhandle, sizeof(int), 0);
      		}
      		else
      		{
      		  	debug_log("Error\n");
      		  	fflush(stdout);
      		  	close(currentsocket);
      		  	return 0;
      		}
      		break;
		}
		case CMD_GETARCHITECTURE:
		{
    	  	unsigned char arch;
    	  	HANDLE h;
    	  	//ce 7.4.1+ : Added the processhandle
			arch=1;
			sendall(currentsocket, &arch, sizeof(arch), 0);
			break;
    	  	debug_log("CMD_GETARCHITECTURE\n");

    	  	if (recvall(currentsocket, &h, sizeof(h), MSG_WAITALL)>0)
    	  	{
    	  	  //intel i386=0
    	  	  //intel x86_64=1
    	  	  //arm 32 = 2
    	  	  //arm 64 = 3
    	  	  debug_log("(%d)",h);
    	  	  arch=ceserver::GetArchitecture(h);
    	  	}
    	  	debug_log("=%d\n", arch);
    	  	sendall(currentsocket, &arch, sizeof(arch), 0);
    	  	break;
    	}
		case CMD_GETABI:
    	{
      		unsigned char abi=ceserver::GetPlatformABI();
      		sendall(currentsocket, &abi, sizeof(abi), 0);
      		break;
    	}
		case CMD_GETSYMBOLLISTFROMFILE:
    	{
    	  //get the list and send it to the client
    	  //zip it first
    	  uint32_t symbolpathsize;

    	  debug_log("CMD_GETSYMBOLLISTFROMFILE\n");
	
    	  if (recvall(currentsocket, &symbolpathsize, sizeof(symbolpathsize), MSG_WAITALL)>0)
    	  {
    	    char *symbolpath=(char *)malloc(symbolpathsize+1);
    	    symbolpath[symbolpathsize]='\0';
	
    	    if (recvall(currentsocket, symbolpath, symbolpathsize, MSG_WAITALL)>0)
    	    {
    	      unsigned char *output=NULL;
	
    	      debug_log("symbolpath=%s\n", symbolpath);
	
    	      
			
    	      if (output)
    	      {
    	        debug_log("output is not NULL (%p)\n", output);
	
    	        fflush(stdout);
	
    	        debug_log("Sending %d bytes\n", *(uint32_t *)&output[4]);
    	        sendall(currentsocket, output, *(uint32_t *)&output[4], 0); //the output buffer contains the size itself
    	        free(output);
    	      }
    	      else
    	      {
    	        debug_log("Sending 8 bytes (fail)\n");
    	        uint64_t fail=0;
    	        sendall(currentsocket, &fail, sizeof(fail), 0); //just write 0
    	      }
    	    }
    	    else
    	    {
    	      debug_log("Failure getting symbol path\n");
    	      close(currentsocket);
    	    }
    	    free(symbolpath);
    	  }
    	  break;
    	}
		case CMD_STARTDEBUG:
    	{
			HANDLE h;
      		if (recvall(currentsocket, &h, sizeof(h), MSG_WAITALL)>0)
      		{
      		  int r=0;
      		  sendall(currentsocket, &r, sizeof(r), 0);
      		}
			break;
		}
		case CMD_STOPDEBUG:
		{
			break;
		}
		default:
		{
			std::cout<<"nfd="<<std::to_string(currentsocket)<<"non implement cmd="<<std::to_string(command)<<std::endl;
			break;
		}

 	}
	return 0;
}

void newconnection(int nfd) {
  std::cout << "newconn fd=" << nfd << std::endl;
  fflush(stdout);
  while (done == 0) {
    fd_set readfds;
    int maxfd = nfd;
    int sret;

    FD_ZERO(&readfds);
    FD_SET(nfd, &readfds);

    sret = select(maxfd + 1, &readfds, NULL, NULL, NULL);
    //  Wait done
    if (sret == -1) {
      if (errno == EINTR) {
        debug_log("Interrupted by signal. Checking again\n");
        continue;
      } else {
        debug_log("select occur errno: %d\n", errno);
        exit(1);
        while (1)
          sleep(60);
      }
    }
    unsigned char command;
    int currentsocket = nfd;
    ssize_t r = recvall(currentsocket, &command, 1, MSG_WAITALL);

    if (r > 0) {

      DispatchCommand(currentsocket, command);
    } else if (r == -1) {
      debug_log("read error on socket %d (%d)\n", nfd, errno);
      fflush(stdout);
      close(currentsocket);
      return;
    } else if (r == 0) {
      std::cout << nfd << " has disconnected" << std::endl;
      fflush(stdout);
      close(currentsocket);
      return;
    }
  }

  std::cout << "thread canceled nfd=" << nfd << std::endl;
}

#include "ceserver_interface_impl.h"

int main(int argc, char *argv[]) {
  cxxopts::Options options("ceserver-rawmem",
                           "CEServer for raw memory dump file, QEMU/KVM");
  options.add_options()
      ("f,file", "Memory dump file name",cxxopts::value<std::string>())
      ("vm", "QEMU/KVM guest name",cxxopts::value<std::string>())
      ("p,port", "CEServer port",cxxopts::value<uint16_t>()->default_value("8997"))
      ("h,help", "Show help");

  cxxopts::ParseResult parse_result;

  try {
    parse_result = options.parse(argc, argv);
  } catch (...) {
    std::cout << options.help() << std::endl;
    return 1;
  }

  if (parse_result.count("file") == 0 && parse_result.count("vm") == 0) {
    std::cout << "Please specify a memory dump file with the -f argument, or a QEMU/KVM guest virtual machine name with the --vm argument" << std::endl;
    std::cout << options.help() << std::endl;
    return 1;
  }
  if (parse_result.count("file") > 0 && parse_result.count("vm") > 0) {
    std::cout << "Arguments specified too many platforms" << std::endl;
    std::cout << options.help() << std::endl;
    return 1;
  }
  if (parse_result.count("help")) {
    std::cout << options.help() << std::endl;
    return 0;
  }
  #ifndef QEMUKVM_ENABLE
  if (parse_result.count("vm")) {
    std::cout << "Your platform does not support CEServer-RawMemory access to QEMU/KVM" << std::endl;
    return 0;
  }
  #endif

  std::cout << "self pid: " << getpid() << std::endl;

  std::shared_ptr<physmem_accessor> accessor=nullptr;

  if(parse_result.count("file") > 0)
  {
    std::string rawmemfile = parse_result["f"].as<std::string>();
    std::cout << "rawmemfile = " << rawmemfile << std::endl;
    auto rawmemaccessor=std::make_shared<rawmem2dma>(rawmemfile);
    if(!rawmemaccessor->valid())
    {
      std::cout << "Accessor of raw memory dump file create failed" << std::endl;
      exit(1);
    }
    accessor = rawmemaccessor; 
  }
  #ifdef QEMUKVM_ENABLE
  else if(parse_result.count("vm") > 0)
  {
    std::string vm = parse_result["vm"].as<std::string>();
    std::cout << "vm name = " << vm << std::endl;
    auto qemukvmaccessor=std::make_shared<qemukvm2dma>(vm);
    if(!qemukvmaccessor->valid())
    {
      std::cout << "Accessor of QEMU/KVM create failed" << std::endl;
      exit(1);
    }
    accessor = qemukvmaccessor; 
  }
  #endif

  if (!ceserver_impl::initialize(accessor)) {
    std::cerr << "ceserver_impl::initialize failed!" << std::endl;
    exit(1);
  }

  uint16_t PORT = parse_result["p"].as<uint16_t>();
  std::cout << "port=" << PORT << std::endl;

  socklen_t clisize;
  struct sockaddr_in addr, addr_client;

  int s;
  int b;
  int l;
  int a;

  s = socket(AF_INET, SOCK_STREAM, 0);
  debug_log("socket=%d\n", s);

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(PORT);
  addr.sin_addr.s_addr = INADDR_ANY;

  int optval = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

  b = bind(s, (struct sockaddr *)&addr, sizeof(addr));
  if (b == 0)
    debug_log("successfully bound socket\n");
  else
    debug_log("bind=%d (error)\n", b);

  if (b != -1) {
    l = listen(s, 32);

    if (l == 0)
      debug_log("Listening success\n");
    else
      debug_log("listen=%d (error)\n", l);

    clisize = sizeof(addr_client);
    memset(&addr_client, 0, sizeof(addr_client));

    fflush(stdout);

    while (done == 0) {
      int b = 1;
      a = accept(s, (struct sockaddr *)&addr_client, &clisize);

      debug_log("accept=%d\n", a);

      fflush(stdout);

      if (a != -1) {
        int sor = setsockopt(a, IPPROTO_TCP, TCP_NODELAY, &b, sizeof(b));
        if (sor)
          debug_log("setsockopt TCP_NODELAY = 1 returned %d (%d)\n", sor,
                    errno);
        thread_pool.insert(new std::thread{newconnection, a});
        // pthread_create(&pth, NULL, (void *)newconnection, (void
        // *)(uintptr_t)a);
      }
    }
  }

  return 0;
}
