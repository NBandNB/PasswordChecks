#include <iostream>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <curl/curl.h>
#include <cryptopp/hex.h>

bool PasswordFilter(std::string);

int main(int argc, const char** argv) {
    if(argc < 2){
        std::cout << "Usage: PasswordChecks <password>" << std::endl;
        return 1;
    }
	int goodPwd = 0;
	bool pwned = PasswordFilter(argv[1]);
	if (pwned == false) {
		std::cout << "Not a good password" << std::endl;
		int goodPwd = 1;
	}else{
        std::cout << "Possibly good password" << std::endl;
    }
	return goodPwd;
}

size_t cURL_Callback(void* contents, size_t size, size_t nmemb, std::string* s)
{
	((std::string*)s)->append((char*)contents, size * nmemb);
	return size * nmemb;
}

bool PasswordFilter(std::string password) {
	// Declare and initialise the returnValue Boolean expresion as true by default - allow the password change by default
	bool returnValue = true;

	// Declare the String to hold the SHA1 hash
	std::string hash = "";

	// Long and convoluted way of getting password String from PUNICODE_STRING
	//std::wstd::string wStrBuffer(password->Buffer, password->Length / sizeof(WCHAR));
	//const wchar_t* wideChar = wStrBuffer.c_str();
	//std::wstd::string wStr(wideChar);
	//std::std::string str(wStr.begin(), wStr.end());

	// Generate an SHA1 hash of the requesting password std::string through Crypto++
	CryptoPP::SHA1 sha1;
	CryptoPP::StringSource(password, true, new CryptoPP::HashFilter(sha1, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hash))));

	// Declare and initialise cURL
	CURL* curl = curl_easy_init();

	// Initialise URL String as being the API address, as well as the first 5 letters of the password hash
	std::string URL("https://api.pwnedpasswords.com/range/" + hash.substr(0, 5));

	// Declare String for the API response
	std::string APIResponse;

	int http_status_code; // Declare the http_status_code variable
	if (curl) { // If cURL has been initialised..
		CURLcode res;
		curl_easy_setopt(curl, CURLOPT_URL, URL.c_str()); // Set the URL for CURL to the URL string
		curl_easy_setopt(curl, CURLOPT_USERAGENT, "API Scraper/1.0"); // Troy requires a user-agent when calling API
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cURL_Callback); // Set the write function for cURL to cURL_Callback
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &APIResponse); // Set up cURL to write the API response to the APIResponse String

		res = curl_easy_perform(curl); // Perform the request on the above URL with the above user-agent

		if (res == CURLE_OK) { // If no errors occurred..

			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status_code); // Retrieve the HTTP status code

			if (http_status_code == 404) { // If the status code is 404 (i.e. password doesn't exist in pwned passwords data) THEN..
				returnValue = true; // Set returnValue Boolean to true (password is fine to use as it doesn't exist as a previously breached password)
			}
			else if (http_status_code / 100 == 3 || http_status_code / 100 == 4 || http_status_code / 100 == 5) // If there are any client, server errors or redirects
			{
				returnValue = true; // Set returnValue Boolean to true (fail open)
			}
			else // If there was a response from the API
			{
				std::size_t found = APIResponse.find(hash.substr(5)); // Attempt to find the hash suffix

				if (found != std::string::npos) // The find function will return string::npos if the requested std::string was no found
				{
					returnValue = false; // If the hash exists, then set the return value to false (i.e. don't allow the password to be changed)
				}
			}
		}
		curl_easy_cleanup(curl); // Clean-up for cURL
	}

	return returnValue; // Return the Boolean value to LSA

}