#include <windows.h> 
#include <tchar.h>
#include <stdio.h> 
#include <strsafe.h>

#include <stdint.h> // portable: uint64_t   MSVC: __int64 
#include <string.h>
#include <signal.h>

static int GetTimeOfDayStr(char* buf)
{
	#if 0
	uint64_t seconds = 0, milliSeconds = 0;
	
    // Note: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing zero's
    // This magic number is the number of 100 nanosecond intervals since January 1, 1601 (UTC)
    // until 00:00:00 January 1, 1970 
    static const uint64_t EPOCH = ((uint64_t) 116444736000000000ULL);

    SYSTEMTIME  system_time;
    FILETIME    file_time;
    uint64_t    time;

    GetSystemTime( &system_time );
    SystemTimeToFileTime( &system_time, &file_time );
    time =  ((uint64_t)file_time.dwLowDateTime )      ;
    time += ((uint64_t)file_time.dwHighDateTime) << 32;

    *seconds  =  ((time - EPOCH) / 10000000L);
    *milliSeconds =  (system_time.wMilliseconds * 1);

	unsigned hour, minute, second;
			  second = seconds % 60;
			  seconds = seconds / 60;
			  minute = seconds % 60;
			  hour = seconds / 60;

			  
	snprintf(buf, 128, "%u:%02u:%02u.%03u ", hour, minute, second, (long unsigned)milliSeconds);
	#else
	SYSTEMTIME tm;
	GetLocalTime(&tm);
	snprintf(buf, 128, "%u-%u-%02u %02u:%02u:%02u.%03u ", 
		tm.wYear, tm.wMonth, tm.wDay, tm.wHour, tm.wMinute, tm.wSecond, tm.wMilliseconds);
	#endif
			  
    return 0;
}


#define BUFSIZE 4096 
 
HANDLE g_hChildStd_IN_Rd = NULL;
HANDLE g_hChildStd_IN_Wr = NULL;
HANDLE g_hChildStd_OUT_Rd = NULL;
HANDLE g_hChildStd_OUT_Wr = NULL;
int g_bShowTime = 0;
 
void CreateChildProcess(void); 
DWORD WriteToPipe(LPVOID lpParameter); 
DWORD WINAPI ReadFromPipe(LPVOID lpParameter);

void ErrorExit(PTSTR); 

BOOL WINAPI consoleHandler(DWORD signal) 
{
    if (signal == CTRL_C_EVENT)
    {
		char ctrlC = 0x03;
		DWORD dwWritten = 0;
		BOOL bSuccess = WriteFile(g_hChildStd_IN_Wr, &ctrlC, 1, &dwWritten, NULL);
	}

    return TRUE;
}

static void sigHandler(int sig) {
	char buf[128];
	snprintf(buf, sizeof(buf), "Signal %d received (SIGINT:%d)\n", sig, SIGINT);

	DWORD dwWritten = 0;
	WriteFile(g_hChildStd_IN_Wr, buf, strlen(buf), &dwWritten, NULL);
	
    if (1 || sig == SIGINT) {
		char ctrlC = 0x03;
		WriteFile(g_hChildStd_IN_Wr, &ctrlC, 1, &dwWritten, NULL);
	}
};

static BOOL WINAPI HandlerRoutine(DWORD dwCtrlType) {
    switch (dwCtrlType)
    {
    case CTRL_C_EVENT:
        printf("[Ctrl]+C\n");
		char ctrlC = 0x03;
		DWORD dwWritten = 0;
		WriteFile(g_hChildStd_IN_Wr, &ctrlC, 1, &dwWritten, NULL);
        // Signal is handled - don't pass it on to the next handler
        return TRUE;
    default:
        // Pass signal on to the next handler
        return FALSE;
    }
}


 
int main(int argc, TCHAR *argv[]) 
{ 
   SECURITY_ATTRIBUTES saAttr; 
 
   //printf("\n->Start of parent execution.\n");

   if (argv[1] != NULL) {
	 if (!strcmp(argv[1], "-t")) {
		g_bShowTime = 1;
	 }
   }

	//SetConsoleCtrlHandler(consoleHandler, TRUE);

   //Remove ENABLE_PROCESSED_INPUT flag
    //DWORD dwMode = 0x0;
    //GetConsoleMode( GetStdHandle(STD_INPUT_HANDLE), &dwMode);
    //dwMode &= ~ENABLE_PROCESSED_INPUT;
    //SetConsoleMode( GetStdHandle(STD_INPUT_HANDLE), dwMode);

    //signal(SIGINT, sigHandler);
    //signal(SIGABRT, sigHandler);
	//signal(SIGTERM, sigHandler);

    //SetConsoleCtrlHandler(HandlerRoutine, TRUE);


// Set the bInheritHandle flag so pipe handles are inherited. 
 
   saAttr.nLength = sizeof(SECURITY_ATTRIBUTES); 
   saAttr.bInheritHandle = TRUE; 
   saAttr.lpSecurityDescriptor = NULL; 

// Create a pipe for the child process's STDOUT. 
 
   if ( ! CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0) ) 
      ErrorExit(TEXT("StdoutRd CreatePipe")); 

// Ensure the read handle to the pipe for STDOUT is not inherited.

   if ( ! SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0) )
      ErrorExit(TEXT("Stdout SetHandleInformation")); 

// Create a pipe for the child process's STDIN. 
 
   if (! CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0)) 
      ErrorExit(TEXT("Stdin CreatePipe")); 

// Ensure the write handle to the pipe for STDIN is not inherited. 
 
   if ( ! SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0) )
      ErrorExit(TEXT("Stdin SetHandleInformation")); 
 
// Create the child process. 
   
   CreateChildProcess();


  HANDLE hReadThread = CreateThread(
        NULL,    // Thread attributes
        0,       // Stack size (0 = use default)
        ReadFromPipe, // Thread start address
        NULL,    // Parameter to pass to the thread
        0,       // Creation flags
        NULL);   // Thread id
    if (hReadThread == NULL)
    {
        // Thread creation failed.
        // More details can be retrieved by calling GetLastError()
        fprintf(stderr, "cant create read thread\n");
    }

	
	HANDLE hWriteThread = CreateThread(
        NULL,    // Thread attributes
        0,       // Stack size (0 = use default)
        WriteToPipe, // Thread start address
        NULL,    // Parameter to pass to the thread
        0,       // Creation flags
        NULL);   // Thread id
    if (hWriteThread == NULL)
    {
        // Thread creation failed.
        // More details can be retrieved by calling GetLastError()
        fprintf(stderr, "cant create write thread\n");
    }


   // Wait for thread to finish execution

   if (hReadThread != NULL) 
   {
   	 WaitForSingleObject(hReadThread, INFINITE);
  	 CloseHandle(hReadThread);
	 hReadThread = NULL;
   }

   if (hWriteThread != NULL) 
   {
   	 WaitForSingleObject(hWriteThread, INFINITE);
  	 CloseHandle(hWriteThread);
	 hWriteThread = NULL;
   }

   printf("\n->End of parent execution.\n");

// The remaining open handles are cleaned up when this process terminates. 
// To avoid resource leaks in a larger application, close handles explicitly. 

   return 0; 
} 
 
void CreateChildProcess()
// Create a child process that uses the previously created pipes for STDIN and STDOUT.
{ 
   TCHAR szCmdline[]=TEXT("plink -v serial");
   PROCESS_INFORMATION piProcInfo; 
   STARTUPINFO siStartInfo;
   BOOL bSuccess = FALSE; 
 
// Set up members of the PROCESS_INFORMATION structure. 
 
   ZeroMemory( &piProcInfo, sizeof(PROCESS_INFORMATION) );
 
// Set up members of the STARTUPINFO structure. 
// This structure specifies the STDIN and STDOUT handles for redirection.
 
   ZeroMemory( &siStartInfo, sizeof(STARTUPINFO) );
   siStartInfo.cb = sizeof(STARTUPINFO); 
   siStartInfo.hStdError = g_hChildStd_OUT_Wr;
   siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
   siStartInfo.hStdInput = g_hChildStd_IN_Rd;
   siStartInfo.dwFlags |= STARTF_USESTDHANDLES;
 
// Create the child process. 
    
   bSuccess = CreateProcess(NULL, 
      szCmdline,     // command line 
      NULL,          // process security attributes 
      NULL,          // primary thread security attributes 
      TRUE,          // handles are inherited 
      0,             // creation flags 
      NULL,          // use parent's environment 
      NULL,          // use parent's current directory 
      &siStartInfo,  // STARTUPINFO pointer 
      &piProcInfo);  // receives PROCESS_INFORMATION 
   
   // If an error occurs, exit the application. 
   if ( ! bSuccess ) 
      ErrorExit(TEXT("CreateProcess"));
   else 
   {
      // Close handles to the child process and its primary thread.
      // Some applications might keep these handles to monitor the status
      // of the child process, for example. 

      CloseHandle(piProcInfo.hProcess);
      CloseHandle(piProcInfo.hThread);
      
      // Close handles to the stdin and stdout pipes no longer needed by the child process.
      // If they are not explicitly closed, there is no way to recognize that the child process has ended.
      
      CloseHandle(g_hChildStd_OUT_Wr);
      CloseHandle(g_hChildStd_IN_Rd);
   }
}
 
DWORD WriteToPipe(LPVOID lpParameter)
// Read from a file and write its contents to the pipe for the child's STDIN.
// Stop when there is no more data. 
{ 
   DWORD dwRead, dwWritten; 
   CHAR chBuf[BUFSIZE];
   BOOL bSuccess = FALSE;
   HANDLE hParentStdIn = GetStdHandle(STD_INPUT_HANDLE);
 
   for (;;) 
   { 
   	  
      bSuccess = ReadFile(hParentStdIn, chBuf, BUFSIZE, &dwRead, NULL);
      if ( ! bSuccess || dwRead == 0 ) break; 

	
      bSuccess = WriteFile(g_hChildStd_IN_Wr, chBuf, dwRead, &dwWritten, NULL);
      if ( ! bSuccess ) break; 
   } 
 
// Close the pipe handle so the child process stops reading. 
 
   if ( ! CloseHandle(g_hChildStd_IN_Wr) ) 
      ErrorExit(TEXT("StdInWr CloseHandle")); 
} 

#define PATTEN_STR "balance_pgdat zone"
#define ENABLE_PATTEN_CMD 1

void cmd_pattern(void) 
{
	#if ENABLE_PATTEN_CMD
	CHAR chBuf1[BUFSIZE];

	char* cmds[3] = {
		"cat /sys/kernel/debug/ion/heaps/iso",
		"cat /sys/kernel/debug/ion/heaps/cm",
		"cat /sys/kernel/debug/ion/heaps/misc",
	};

	int i;
	for (i = 0; i < 3; ++i) {
		DWORD dwWritten = 0;
		CHAR chBuf1[BUFSIZE];
		snprintf(chBuf1, sizeof(chBuf1), "%s;\n", cmds[i]);
		
		WriteFile(g_hChildStd_IN_Wr, chBuf1, strlen(chBuf1), &dwWritten, NULL);
	}
	#endif 
}

DWORD WINAPI ReadFromPipe(LPVOID lpParameter) 

// Read output from the child process's pipe for STDOUT
// and write to the parent process's pipe for STDOUT. 
// Stop when there is no more data. 
{ 
   DWORD dwRead = 0, dwWritten;
   DWORD dwRead0;
   CHAR chBuf0[BUFSIZE];
   CHAR chBuf1[BUFSIZE];
   
   CHAR chBuf[2*BUFSIZE] = ""; 
   BOOL bSuccess = FALSE;
   HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

   uint64_t patternCnt = 0;

	//test
	char ctrlC = 0x03;
	WriteFile(g_hChildStd_IN_Wr, &ctrlC, 1, &dwWritten, NULL);
	
   snprintf(chBuf1, sizeof(chBuf1),"date;\n");
   WriteFile(g_hChildStd_IN_Wr, chBuf1, strlen(chBuf1), &dwWritten, NULL);

   //cmd_pattern();

   //FILE* fout = fopen("dump.txt", "wb");
	

   for (;;) 
   { 
   	  //read almost one char at a time
      bSuccess = ReadFile( g_hChildStd_OUT_Rd, chBuf0, BUFSIZE, &dwRead0, NULL);
      if( ! bSuccess || dwRead0 == 0 ) break; 
	  if (dwRead0 < 1) continue;

	  chBuf0[dwRead0] = 0;

	  #if 0
	  snprintf(chBuf1, sizeof(chBuf1), "=='%s'==\n", chBuf0);

	  fwrite(chBuf1, strlen(chBuf1), 1, fout);
	  fflush(fout);
	  #endif

	  if (!g_bShowTime) {
		 WriteFile(hParentStdOut, chBuf0, dwRead0, &dwWritten, NULL);
	  }
	  else {
	  	  //output all new lines.
	  	  char* pEnd = chBuf0 + dwRead0;
	  	  char* pStart = chBuf0;
		  char* pNewLine = strchr(pStart, '\n');
		  while (pNewLine) {
			++pNewLine;

		  	char checkBuf[2*BUFSIZE+128] = "";
			int checkLen = 0;
			
			//prefix timestamp
		  	GetTimeOfDayStr(checkBuf + checkLen);
			int timestampLen = strlen(checkBuf + checkLen);
			checkLen += timestampLen;
			char* pPattenStart = checkBuf + checkLen;

			//prepare cached chars + this newline chars
			int newLineLen = pNewLine-pStart;
			
			if (dwRead > 0) {
				memcpy(checkBuf + checkLen, chBuf, dwRead);
				checkLen += dwRead;
				memcpy(checkBuf + checkLen, pStart, newLineLen);
				checkLen += newLineLen;
				
				dwRead = 0;
			}
			else {
				memcpy(checkBuf + checkLen, pStart, newLineLen);
				checkLen += newLineLen;
			}

			//check PATTEN_STR every 10 times and do cmd:	
			if (strstr(pPattenStart, PATTEN_STR)) {
				++patternCnt;
			}

			if ( ENABLE_PATTEN_CMD && patternCnt == 10) {
				patternCnt = 0;
				cmd_pattern();
			}

			//output
			WriteFile(hParentStdOut, checkBuf, checkLen, &dwWritten, NULL);

			//next loop
			pStart = pNewLine;
			pNewLine = strchr(pStart, '\n');
		  }

		  //cache none-newline chars with previous read.
		  if (pStart < pEnd) {
			 int remainLen = pEnd - pStart;

		  	 if (dwRead + remainLen > sizeof(chBuf)/sizeof(chBuf[0])) {
			 	//buffer full, flush without timestamp!
			 	WriteFile(hParentStdOut, chBuf, dwRead, &dwWritten, NULL);
				dwRead = 0;
		  	 }

			 memcpy(chBuf+dwRead, pStart, remainLen);
		  	 dwRead += remainLen;
		  }
		  
	  }

	  chBuf0[0] = 0;
	  dwRead0 = 0;

   } 

   return 0;
} 
 
void ErrorExit(PTSTR lpszFunction) 

// Format a readable error message, display a message box, 
// and exit from the application.
{ 
    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError(); 

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );

    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, 
        (lstrlen((LPCTSTR)lpMsgBuf)+lstrlen((LPCTSTR)lpszFunction)+40)*sizeof(TCHAR)); 
    StringCchPrintf((LPTSTR)lpDisplayBuf, 
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("%s failed with error %d: %s"), 
        lpszFunction, dw, lpMsgBuf); 
    MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK); 

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
    ExitProcess(1);
}

