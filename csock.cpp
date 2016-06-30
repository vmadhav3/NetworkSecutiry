/******
Socket Client programs runs in OVS switches. Currently tested in One OVS switch topology. May work well for multiple switches
*******/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <iostream>
#include <string>
#include <sstream>
#include <fstream> 
#include <vector>
#include <algorithm>

using namespace std;

void error(const char *msg)
{
	perror(msg);
	exit(0);
}

bool copyFile(const char *SRC, const char* DEST)
{
	ifstream src(SRC, ios::binary);
	ofstream dest(DEST, ios::binary);
	dest << src.rdbuf();
	//hence snort will write in a new file
	remove("/var/log/snort/alert.csv");
	return src && dest;
}

int main(int argc, char *argv[])
{
	int sockfd, portno, n;
	struct sockaddr_in serv_addr;
	struct hostent *server;

	char buffer[256];
	if (argc < 3) {
		fprintf(stderr, "usage %s hostname port\n", argv[0]);
		exit(0);
	}
	portno = atoi(argv[2]);

	while (true)
	{
		if (true == copyFile("/var/log/snort/alert.csv", "/var/log/snort/send/alert.csv"))
		{
			string strLine;
			ifstream myfile("/var/log/snort/send/alert.csv");
			vector<string> vecMac;
			if (myfile.is_open())
			{

				while (getline(myfile, strLine))
				{
					stringstream ss(strLine);
					string strTemp;
					string sMac;
					int count = 0;
					while (getline(ss, strTemp, ',')) {
						if (count == 10 || count == 11)
						{
							//cout << strTemp << '\n';
							sMac.append(strTemp);
							if (count == 10)
								sMac.append(",");
							else if (count == 11)
								sMac.append("\n");
						}
						count++;
					}

					if (std::find(vecMac.begin(), vecMac.end(), sMac) == vecMac.end())
					{
						// sMac not in vecMac, add it
						vecMac.push_back(sMac);
					}

				}
				myfile.close();
			}
			else cout << "Error\n";

			string strMac;
			for (std::vector<string>::iterator it = vecMac.begin(); it != vecMac.end(); ++it)
			{
				strMac.append(*it);
				//strMac.append("\n");
			}

			cout << strMac << endl;

			// Remove file after logs copied
			remove("/var/log/snort/send/alert.csv");

			sockfd = socket(AF_INET, SOCK_STREAM, 0);
			if (sockfd < 0)
				error("ERROR opening socket");
			server = gethostbyname(argv[1]);
			if (server == NULL) {
				fprintf(stderr, "ERROR, no such host\n");
				exit(0);
			}
			bzero((char *)&serv_addr, sizeof(serv_addr));
			serv_addr.sin_family = AF_INET;
			bcopy((char *)server->h_addr,
				(char *)&serv_addr.sin_addr.s_addr,
				server->h_length);
			serv_addr.sin_port = htons(portno);

			if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
				error("ERROR connecting");

			bzero(buffer, 256);
			//fgets(buffer, 255, stdin);
			n = write(sockfd, strMac.c_str(), strMac.length());
			if (n < 0)
				error("ERROR writing to socket");

			close(sockfd);

		}

		//Every Two seconds it will check for the file 
		sleep(2);
	}
	return 0;
}
