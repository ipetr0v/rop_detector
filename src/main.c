#include <getopt.h>
#include <time.h>

#include "engine/engine.h"

#define moduleName "../module/rop_detector.ko"
extern pid_t test_pid;
char *dev;

static struct option long_options[] = 
{
	{"pid", required_argument, 0, 'p'},
    {"random_data", required_argument, 0, 'r'},
	{"interface", required_argument, 0, 'i'},
	{"file", required_argument, 0, 'f'},
	{"directory", required_argument, 0, 'd'},
	{"help", no_argument, 0, 'h'}
};

void printHelp()
{
    printf("Usage ./prog OPTIONS \
            OPTIONS: \n\
            -p pid \n\
            -r iteration_number \n\
            -i interface \n\
            -f file \n\
            -d directory \n\
            -h help \n");
    
    /*
	cout << "usage: ./demorpheus OPTION [file name or interface] [--error-rate fp|fn] [--topology linear|hybrid] [--mode x86|arm]\n" <<
			"OPTIONS: \n"<< 
			"-i \t\t interface\n"<<
			"-f \t\t file\n"<<
			"-h \t\t help message\n\n" << endl;
	cout << "error-rate: \n fp calculates false positives rate \n fn calculates false negatives rate" << endl;
	cout << " topology is hybrid by default" << endl << endl;*/
}

//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------

void exit_handler()
{
    // Detection engine deinitialization
    engine_destroy();
    exit(0);
}

int main(int argc, char *argv[])
{
    FILE* pFile = NULL;
    DIR* pDir = NULL;
    struct dirent *entry = NULL;
    char* file_name = NULL;
    char* dir_name = NULL;
	int fileNum = 0;
    int random_address_iteration_number = 0;
    
    int interface = 0, file = 0, dir = 0, random_data = 0;
    
    extern int optind, opterr, optopt;
	extern char *optarg;
    int opt;
    
	int total_cnt = 0;
	int s_cnt = 0;
    
    struct sigaction sigIntHandler;

    sigIntHandler.sa_handler = exit_handler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
        
    ///test_pid = argc > 1 ? atoi(argv[1]) : 0;
    
    // Get arguments
	while (1) {
		int option_index = 0;
		opt = getopt_long(argc, argv, "p:r:i:f:d:m:", long_options, &option_index);
		
		if (opt == -1) break;
		
		switch (opt) {
			case 'p':
                test_pid = atoi(optarg);
				if ( test_pid < 0 ) {
					if (LOGLVL >= ERRLOG) printf("Wrong test pid\n"); // --- DEBUG OUTPUT ---
				}
				break;
            case 'r':
                random_data = 1;
                random_address_iteration_number = atoi(optarg);
                if ( random_address_iteration_number < 0 ) {
					if (LOGLVL >= ERRLOG) printf("Wrong random address number\n"); // --- DEBUG OUTPUT ---
				}
                break;
            case 'i':
				interface = 1;
				dev = optarg;
				break;
			case 'f':
				file = 1;
				file_name = optarg;
				pFile = fopen( file_name, "rb" );
				if ( pFile == NULL ) {
					if (LOGLVL >= ERRLOG) printf("Cannot open file\n"); // --- DEBUG OUTPUT ---
				}
				break;
            case 'd':
				dir = 1;
                dir_name = optarg;
				break;
			case 'h':
				printHelp();
				return 0;
				break;
			default:
				abort();
		}
	}
    
    // Check parameters
	if(!interface && !file && !random_data && !dir) {
        if (LOGLVL >= ERRLOG) printf("No interface or filename or dir or random_data parameters\n"); // --- DEBUG OUTPUT ---
		return 1;
	}
	if( interface && file ||
        interface && random_data ||
        interface && dir ||
        file && random_data ||
        file && dir ||
        random_data && dir ) {
        
        if (LOGLVL >= ERRLOG) printf("Incompatible parameters, choose interface or file or random data or dir\n"); // --- DEBUG OUTPUT ---
		return 1;
	}
    if ( !test_pid && file ||
         !test_pid && dir ||
         !test_pid && random_data ) {
        
        if (LOGLVL >= ERRLOG) printf("File or Dir or random data parameters need a test_pid parameter\n"); // --- DEBUG OUTPUT ---
		return 1;
    }
    
    // Detection engine initialization
    engine_init();
    sigaction(SIGINT, &sigIntHandler, NULL);
    
    //catch the packets, retrieve payload and process it
	if (interface)
    {
		int index = 0;
        
        sniffer_init(dev);
		while(1)
        {
            int i;
            unsigned char* payload = NULL;
            int payload_size = 0;
            unsigned int ip_dest_addr = 0;
            unsigned short dest_port = 0;
            
            payload_size = sniffer_process_packet(&payload, &ip_dest_addr, &dest_port);
			
			while (payload_size - index > 0) {
				int byte_count = 0;
				if ( payload_size - index < STACK_BUFFER_SIZE )
					byte_count = payload_size - index;
				else byte_count = STACK_BUFFER_SIZE;
				
				memcpy( input_buffer(), payload, byte_count );
				index += byte_count;
				//PRINT_DEBUG << "read payload: " << buffer << endl;
				//PRINT_DEBUG << "read real payload: " << payload + index << endl;
				//PRINT_DEBUG << "offset = " << index << endl;
                if (LOGLVL >= ERRLOG) printf("[%d.%d.%d.%d:%d] Size: %d | ", ((ip_dest_addr) >> 0 ) & 0xFF,
                                                                             ((ip_dest_addr) >> 8 ) & 0xFF,
                                                                             ((ip_dest_addr) >> 16) & 0xFF,
                                                                             ((ip_dest_addr) >> 24) & 0xFF,
                                                                             dest_port,
                                                                             byte_count); // --- DEBUG OUTPUT ---
                // PAYLOAD PRINT
                //printf("Payload: "); // --- DEBUG OUTPUT ---
                //for (i=0; i<byte_count; i++) {
                //    if (LOGLVL >= ERRLOG) printf("%c", ((char*)input_buffer())[i]); // --- DEBUG OUTPUT ---
                //}
                //if (LOGLVL >= ERRLOG) printf("\n"); // --- DEBUG OUTPUT ---
				// PAYLOAD PRINT
                
                if( engine_classifier(byte_count, ip_dest_addr, dest_port) ) {
                    s_cnt++;
                    //if (LOGLVL >= ERRLOG) printf("Shellcode found in traffic\n"); // --- DEBUG OUTPUT ---
                }
				total_cnt++;	
			}
			index = 0;
		}
		sniffer_destroy();
	}
    
    // Read data file
    if (pFile)
    {
		while(!feof(pFile))
        {
			int byte_count = fread( input_buffer(), sizeof( unsigned char ), STACK_BUFFER_SIZE, pFile );
			if ( byte_count == 0 ) continue;
			
			if (LOGLVL >= ERRLOG) printf("%s: %d | ", file_name, byte_count); // --- DEBUG OUTPUT ---
			//PRINT_DEBUG << "read payload: " << buffer << endl;
            
            if( engine_classifier(byte_count, 0, 0) ) {
				s_cnt++;
                if (LOGLVL >= ERRLOG) printf("Shellcode found in file %s\n", file_name); // --- DEBUG OUTPUT ---
            }
			total_cnt++;
			//lastTime = topology->getLastTime();
			//timeval_addition(&totalTime, &totalTime, &lastTime);
		}
		
		fclose(pFile);
	}
    
    if (dir)
    {
        pDir = opendir(dir_name);
        if (LOGLVL >= ERRLOG) printf("Opening directory - %s\n", dir_name); // --- DEBUG OUTPUT ---
        while ( (entry = readdir(pDir)) != NULL) 
        {
            if ( strcmp(entry->d_name,".")!=0 && strcmp(entry->d_name,"..")!=0 )
            {
                int file_name_len = strlen(dir_name) + 1 + strlen(entry->d_name) + 4;
                char* full_file_name = (char*)malloc(file_name_len);
                full_file_name[0] = '\0';
                strcat(full_file_name, dir_name);
                strcat(full_file_name, "/");
                strcat(full_file_name, entry->d_name);
                
                pFile = fopen( full_file_name, "rb" );
                free(full_file_name);
				if ( pFile == NULL ) {
					if (LOGLVL >= ERRLOG) printf("Cannot open file - %s\n", entry->d_name); // --- DEBUG OUTPUT ---
                    continue;
				}
                fileNum++;
            }
            
            // FULL FILE
			while( !feof(pFile) )
			{
				int byte_count = fread( input_buffer(), sizeof( unsigned char ), STACK_BUFFER_SIZE, pFile );
                if ( byte_count == 0 ) continue;
                
                if (LOGLVL >= ERRLOG) printf("%s: %d | ", entry->d_name, byte_count); // --- DEBUG OUTPUT ---
                //PRINT_DEBUG << "read payload: " << buffer << endl;
                
                if( engine_classifier(byte_count, 0, 0) ) {
                    s_cnt++;
                    if (LOGLVL >= ERRLOG) printf("Shellcode found in file %s\n", entry->d_name); // --- DEBUG OUTPUT ---
                }
                total_cnt++;
                //lastTime = topology->getLastTime();
                //timeval_addition(&totalTime, &totalTime, &lastTime);
			}// FILE
            fclose(pFile);
        }
        
        closedir(pDir);
    }
    
    if (random_data)
    {
        engine_test_run(random_address_iteration_number);
    }
    
    // Detection engine deinitialization
    engine_destroy();
}
















