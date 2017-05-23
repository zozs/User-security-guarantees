#ifndef GENERALSETTINGS_H
#define GENERALSETTINGS_H

#include <string>

using std::string;

namespace Settings {
	static int rh_port = 22222;							//remote host port
	static string rh_host = "localhost";				//remote host IP
	static int container_port = 22223;					//container-application port
	static string container_host = "localhost";			//container-application IP
	
	static string measurement_list = "";				//Path to the measurement list
	static string valid_mrenclaves = "";				// Path to file with list of valid MRENCLAVE values.
	static string remotehostHashKeyLocation = "";		//Docker data volume path on the remote host
	static string applicationHashKeyLocation = "";		//Docker data volume path on the container
	
	static string nginx_pub_crt = "";					//Certificate file path for nginx
	static string server_crt = "";						//Certificate file path for the Servers (Remote host and Application the same)
	static string server_key = "";						//Private Key file path for the Servers (Remote host and Application the same)

	static string spid = "";							//SPID provided by Intel
	static const char *ias_crt = "";					//IAS certificate used when registering developer account at Intel
	static string ias_url = "https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v1/";	//REST API IAS

	// CA certificate and key used when signing certificates for the application.
	static std::string ca_crt_path = "";
	static std::string ca_key_path = "";
}

#endif
