#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

 
#define SHA_KEY_SIZE 16
#define HMAC_SIZE 64 
#define N_MODE "-d"
#define L_MODE "-l"


char * ip; // ip addrress
char * port; // port to connect to server
int enc_mode; // Mode can be local or network
char * outfile; // encrpted file in form of outfile.uf



//Generate hmac for to append to the encrpted file
char * fetch_hmac(char * key, size_t size, char * cipher){
	
	gcry_error_t err;
	gcry_md_hd_t hmac_handle;//create handle for hmac
	
	
	err = gcry_md_open(&hmac_handle, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
	
	
	if(err){
		printf ("Unable to open handle for hmac: \n");
		gcry_strerror(err);
		exit(-1);
	}
	err = gcry_md_enable(hmac_handle,GCRY_MD_SHA512);

	//Set the key for Hmac using Key
	err = gcry_md_setkey(hmac_handle, key,SHA_KEY_SIZE );
	if(err){
		printf ("Unable to set key for hmac: \n");
		gcry_strerror(err);
		exit(-1);
	}
	// generating the HMAC using the cipher text
  	gcry_md_write(hmac_handle,cipher,size);
  	gcry_md_final(hmac_handle);

	char * hmac;
	hmac = gcry_md_read(hmac_handle , GCRY_MD_SHA512 );
		
	//Error check for HMAC 	
	if(hmac == NULL ){
		printf ("hmac is null \n");
			}
	
	return hmac;
}


void transmit_file(){
	
	int socket_handle; 
	struct sockaddr_in server_address;//Create the address structure and specify where we want to connect


	// Open the socket and connect to server
	if((socket_handle = socket(AF_INET, SOCK_STREAM, 0))< 0)
    {
    	
        printf("Error creating socket \n");
        exit(-1);
    }

    // making the variable global by casting from char to int
    int PORT = atoi(port); 

    
    server_address.sin_family = AF_INET;//setting the address family for server_address which is same as the client socket i.e. 	AF_INET
    server_address.sin_port = htons(PORT); //htons - conversion function that passes our port number in right network byte order i.e. it converts it to appropriate data format
    server_address.sin_addr.s_addr = inet_addr(ip);


	if(connect(socket_handle, (struct sockaddr *)&server_address, sizeof(server_address))<0)
	    {
	        printf("\n Error while connecting to Server\n");
	        exit(-1);
	    }

	   FILE *fp = fopen(outfile,"rb");
	   if(fp==NULL)
	   {
	       printf("Unable to open file");
	       exit(-1);
	   }
	printf("Connect to the specified ip and port %s:%s\n",ip,port);
	while(1){
        unsigned char text_buffer[256]={0};
         int nread = fread(text_buffer,1,256,fp);

        if(nread > 0)
        {
            write(socket_handle, text_buffer, nread);//Success then write the data
        }

        if (nread < 256){break;}     }
    printf("File sent to the address successfully\n");
}



void print_sha_encrptedfile_hmac(char *encrypt_hmac_buffer, size_t buffer_size){

	char *hash = (char *) malloc(64* (sizeof(char)));

	//method gcry_md_hash_buffer includes
	//GCRY_MD_SHA512 - Algorithm used for hash
	//hash - Outout the final hash value
	//input_buffer - file contents read from file and written to buffer
	//buffer_size - size of the input_buffer
	gcry_md_hash_buffer( GCRY_MD_SHA512, hash, encrypt_hmac_buffer, buffer_size );
	
	
	int count;
	printf("\nPrinting the hash of the encrypted with hmac file\n\n");
	for(count = 0; count < 64; count++){
		printf("%02X ",(unsigned char)hash[count] );
	}
	printf("\n");
	printf("file length : %u\n",strlen(encrypt_hmac_buffer)); 
	printf("\n\n");
		
	
}

void print_sha_encrypted_file(char *encrypt_buffer, size_t buffer_size)
{
	char *hash = (char *) malloc(64* (sizeof(char)));

	//method gcry_md_hash_buffer includes
	//GCRY_MD_SHA512 - Algorithm used for hash
	//hash - Outout the final hash value
	//input_buffer - file contents read from file and written to buffer
	//buffer_size - size of the input_buffer
	gcry_md_hash_buffer( GCRY_MD_SHA512, hash, encrypt_buffer, buffer_size );
	
	
	int count;
	printf("\nPrinting the hash of the encrypted file\n\n");
	for(count = 0; count < 64; count++){
		printf("%02X ",(unsigned char)hash[count] );
	}
	printf("\n");
	printf("file length : %u\n",strlen(encrypt_buffer)); 
	printf("\n\n");

}



void print_sha_input_file(char *input_buffer, size_t buffer_size)
{
	
	char *hash = (char *) malloc(64* (sizeof(char)));
	//method gcry_md_hash_buffer includes
	//GCRY_MD_SHA512 - Algorithm used for hash
	//hash - Outout the final hash value
	//input_buffer - file contents read from file and written to buffer
	//buffer_size - size of the input_buffer
	gcry_md_hash_buffer( GCRY_MD_SHA512, hash, input_buffer, buffer_size );
	
	
	int count;
	printf("\nPrinting the hash of the input file\n\n");
	for(count = 0; count < 64; count++){
		printf("%02X ",(unsigned char)hash[count] );
	}
	printf("\n");
	printf("file length : %u\n",buffer_size); 
	printf("\n\n");

}
//Writing the encrypted data to file after hmac generated
void write_to_file(char * hmac,char * buffer, size_t buffer_size){
	FILE * f;
		
		//Open the file 
		f = fopen(outfile,"wb");
		if (f){
		//write the encrypted data
		fwrite(buffer, buffer_size, sizeof(char), f);
		//append the hmac data
		fwrite(hmac, HMAC_SIZE +1 , sizeof(char), f);
		
		fclose(f);
	}
	else{
		printf ("There was an error opening the file\n");
		exit(-1);
	}
}

char * encrypt_file(char * key,char * input_buffer,size_t buffer_size){
	gcry_cipher_hd_t handle;//create handle
	gcry_error_t err;
	int IV[16] = {5844}; //Initialization Vector



	char *hmac;
    char * encrypt_buffer;

    encrypt_buffer = (char *) malloc(buffer_size); 


	err = gcry_cipher_open(&handle, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0);
	if(err){
		printf ("Unable to open\n");
		gcry_strerror(err);
		exit(-1);
	}

	// Setting the key
    err = gcry_cipher_setkey(handle, key, SHA_KEY_SIZE);
    if(err){
		printf ("Unable to set the Key\n");
		gcry_strerror(err);
		exit(-1);
	}

	// Setting the IV
    err = gcry_cipher_setiv(handle, &IV, SHA_KEY_SIZE);
    if(err ){
		printf ("Unable to set the IV:\n");
		gcry_strerror(err);
		exit(-1);
	}

	// Encryption 
    err = gcry_cipher_encrypt(handle, encrypt_buffer, buffer_size, input_buffer, buffer_size);
    if(err){
		printf ("Unable to encrypt the file :\n");
		gcry_strerror(err);
		exit(-1);
	}


	//Print the hash of the encrypted file
	print_sha_encrypted_file(encrypt_buffer, buffer_size);
	
	//Fetch Hmac of the encrypted output
	hmac = fetch_hmac(key, buffer_size,encrypt_buffer);

	// write the final encrypted file using hmac
	write_to_file(hmac, encrypt_buffer, buffer_size);
	printf("Successfully encrypted the inputfile to %s\n",outfile);

	
	//Generating the file buffer for encrypted file with hmac appended 
	char * buffer = 0;
	long length;
	FILE * f = fopen (outfile, "rb");

	if (f)
	{
	  fseek (f, 0, SEEK_END);
	  length = ftell (f)-1;
	  fseek (f, 0, SEEK_SET);
	  buffer = malloc (length);
	  fread (buffer, sizeof(char), length, f);
		fclose (f);
}


	//Print the hash of the Encrypted file + HMAC
	print_sha_encrptedfile_hmac(buffer, length);
	
	//If the mode is 1 then transmit to the network
   	if(enc_mode == 1){
   		
   		transmit_file(outfile);
   	}

    return encrypt_buffer;

}
	


int main(int argc, char *argv[]){

//Initialize required variables
char * file_buffer;
char * input_buffer;
char * cipher;
char pwd[10];//Password
char key[SHA_KEY_SIZE];
FILE *fp;//File Pointer
FILE *fp1;//File Pointer

size_t input_size;
	



	//verifying if the arguments from command line are correct
	
	// Case 1 - incorrect command line input
	if(argc < 3){
		printf("Format for input is suncrypt <input file> [-d < IP-addr:port >][-l]\n");
  		exit(-1);
	}
	//Case 2 - Missing Ip address or Port no followed by -d when arguments are 4
	if( argc<4){
		if((strcmp(argv[2], N_MODE) == 0)){
		printf("incorrect input ip address and port no neeeded \n");
  		exit(-1);
		}
	}
	//Case 3: If  mode is -d set mode to 1 and fetch ip address and port no
if( argc==4){	
	if((strcmp(argv[2], N_MODE) == 0)){
		enc_mode = 1; //if mode is 1 - stands for network mode
				
		char * addr = argv[3];
//Fetch the ip and port from the command line using strtok funciton and delimiter as :
		ip = strtok(addr,":");//Ip address
		port = strtok(NULL, ":");//Port no
		outfile = (char *)malloc(strlen(argv[1])+3);
		//We use strcat to append 3 extra character due to extension .uf
		strcat(outfile,argv[1] );
		strcat(outfile,".uf" );
		
	}
}
		//Case 4 : When the input is mode is -l set the mode to 0
	if((strcmp(argv[2], L_MODE) == 0)){
		enc_mode = 0; //if mode is 0 - stands for local mode
		outfile = (char *)malloc(strlen(argv[1])+3);
		//We use strcat to append 3 extra character due to extension .uf
		strcat(outfile,argv[1] );
		strcat(outfile,".uf" );
	}
		
	
	 //initializing the library libgcrypt as specified in manual
	//Check for the version
	if (!gcry_check_version (GCRYPT_VERSION))
	 {
	   printf("libgcrypt version doesnt match\n");
	   exit(-1);
	 }
	gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
	gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
	gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

	
	//Fetch the password from the command line
	printf("Enter the Password: ");
	scanf("%s", pwd);
	//Open the file in read mode 
	fp=fopen(argv[1], "rb");
	
	if (fp == NULL) {
  		printf("Error opening the input file.\n");
  		exit(-1);
	}
			
	//Get the Key using Password
	//SALT as "NaCl" 
	//Algo and GCRY_MD_SHA512
	//4096 iterations
	int i, err;
	err = gcry_kdf_derive(pwd, strlen(pwd), GCRY_KDF_PBKDF2, GCRY_MD_SHA512, "NaCl",strlen("NaCl"), 4096, SHA_KEY_SIZE, key);

	//In case of Error print following message

	if(err){
		printf("\n Failed to derive the key :\n");
		gcry_strerror(err);
	}
	else{
		printf("Key: ");
	//Output the key generated
	int i;
	for(i = 0; i < SHA_KEY_SIZE; i++){
		printf("%02X ",(unsigned char) key[i]);
	}
printf("\n");
	}
size_t formatted_size; //In order to maintain the size of input we add trailing zeros

	//Traverse the input file from start to end to fetch file size
	fseek(fp, 0, SEEK_END);
	input_size = ftell(fp) - 1;
	//If the input size exactly is the multiple of SHA_KEY_SIZE then the input size remains same
	if(input_size % SHA_KEY_SIZE == 0){
		 formatted_size = input_size;
		 	}
	else{
			//If the input size is less than SHA_KEY_SIZE then the new size is equal to SHA_KEY_SIZE

		if(input_size < SHA_KEY_SIZE){
			formatted_size = SHA_KEY_SIZE;

		}
		//Else format the size
		else{
			formatted_size = (input_size/SHA_KEY_SIZE)*SHA_KEY_SIZE + SHA_KEY_SIZE ;
			
		}
	}

    //Read the data from file

	file_buffer = (char *)malloc(formatted_size*sizeof(char));
	//input_buffer =(char *)malloc(input_size*sizeof(char));
	fseek(fp, 0, SEEK_SET);
	//fseek(fp1, 0, SEEK_END);
	fread(file_buffer, sizeof(char), formatted_size, fp);
	//fread(input_buffer, sizeof(char), input_size, fp1);


//Save the input file with exact length
char * buffer = 0;
long length;
FILE * f = fopen (argv[1], "rb");

if (f)
{
  fseek (f, 0, SEEK_END);
  length = ftell (f)-1;
  fseek (f, 0, SEEK_SET);
  buffer = malloc (length);
  fread (buffer, sizeof(char), length, f);
    fclose (f);
}


	print_sha_input_file(buffer, length);
	//Encrypt the file	
	cipher = encrypt_file(key,file_buffer,formatted_size);
}

