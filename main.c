#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define TYPE_UNKNOWN	0
#define	TYPE_SCL	1
#define	TYPE_TRD	2

#ifdef _WIN32
#define SLASH '\\'
#endif
#ifdef __linux
#define SLASH '/'
#endif

typedef struct {
	char name[10];
	char ext[3];
} xName;

xName cutName(char* path) {
	char fnam[strlen(path) + 1];
	char* ptr = strrchr(path, SLASH);		// last slash
	if (ptr) {
		strcpy(fnam, ptr + 1);
	} else {
		strcpy(fnam, path);
	}
	ptr = strrchr(fnam, '.');
	xName nm;
	memset(nm.name, 0x20, 10);
	memset(nm.ext, 0x20, 3);
	if (ptr) {
		*ptr = 0x00;
		memcpy(nm.ext, ptr + 1, (strlen(ptr + 1) > 3) ? 3 : strlen(ptr + 1));
	}
	memcpy(nm.name, fnam, (strlen(fnam) > 10) ? 10 : strlen(fnam));
	return nm;
}

int readfile(char* fname, char* buf, int maxlen) {
	FILE *infile = fopen(fname,"rb");
	if (!infile) return -1;		// failed to open file
	fseek(infile, 0, SEEK_END);
	int iflen = ftell(infile);
	rewind(infile);
	if (iflen <= maxlen) {
		fread(buf, iflen, 1, infile);
	} else {
		iflen = 0;
	}
	fclose(infile);
	return iflen;
}

int savefile(char* fname, char* buf, int len) {
	FILE *file = fopen(fname, "wb");
	if (!file) return 0;
	if (buf && (len > 0)) fwrite(buf, len, 1, file);
	fclose(file);
	return 1;
}

int testsig(char* buf, int len) {
	if ((strncmp("SINCLAIR", buf, 8) == 0) && (buf[8] >= 0)) return TYPE_SCL;	// SCL
	if ((len > 0x900) && (buf[0x8e7] == 0x10)) return TYPE_TRD;			// TRD
	return TYPE_UNKNOWN;								// unknown
}

void extractfile(char* buf, unsigned char* ptr, int fpos, char* fname) {
	int len = ptr[11] | (ptr[12] << 8);
	unsigned char slen = ptr[13];
	unsigned char rlen = ptr[12] + (ptr[11] ? 1 : 0);
	if (slen != rlen) len = (slen << 8);
	FILE *ofile = fopen(fname, "wb");
	if (!ofile) {
		printf("Can't write to file '%s'\n",fname);
	} else {
		fwrite(buf+fpos, len, 1, ofile);
		fclose(ofile);
	}
}

void makedsc(char* ptr, char* fname, int len, unsigned char slen, int isBasic) {
	xName nm = cutName(fname);
	memcpy(ptr,nm.name, 8);
	ptr[11] = len & 0xff;		// len
	ptr[12] = ((len & 0xff00) >> 8);
	ptr[13] = slen;			// sectors len
	if (isBasic) {
		ptr[8] = 'B';
		ptr[9] = ptr[11];
		ptr[10] = ptr[12];
	} else {
		ptr[8] = nm.ext[0];		// ext
		ptr[9] = nm.ext[1];
		ptr[10] = nm.ext[2];
	}
}

void addcrc(char* data, int len) {
	unsigned int crc = 0;
	for (int i = 0; i != len; ++i) {
		crc += (unsigned char)data[i];
	}
	data[len] = crc & 0xff;			// crc 4 bytes LSF (!)
	data[len+1] = (crc >> 8) & 0xff;
	data[len+2] = (crc >> 16) & 0xff;
	data[len+3] = (crc >> 24) & 0xff;
}

void pack(char* fileName, char* aname, int isBasic, int autoStart) {
	// read file. if can't be opened or too large, exit
	char inbuf[0x10000];
	int iflen = readfile(fileName, inbuf, 0xff00);
	if (iflen == -1) {
		printf("Can't read file '%s'\n",fileName);
		return;
	} else if (iflen == 0) {
		printf("Input file '%s' is too long (0xff00 is a maximum)\n",fileName);
		return;
	}
	// cut extension from filename
	if (isBasic) {
		inbuf[iflen] = 0x80;
		inbuf[iflen+1] = 0xaa;
		inbuf[iflen+2] = autoStart & 0xff;
		inbuf[iflen+3] = ((autoStart & 0xff00) >> 8);
	}
	
	char obuf[0xa0000];
	int olen = readfile(aname, obuf, 0xa0000);
	if (olen < 1) {
		printf("Can't read output file '%s'\n", aname);
		return;
	}
	
	int mode = testsig(obuf, olen);
	int dataLen = iflen + (isBasic ? 4 : 0);	// 80 aa <autostart>
	unsigned char seclen = ((dataLen & 0xff00) >> 8) + ((dataLen & 0xff) ? 1 : 0);	// sectors len
	unsigned char lastsec, lasttrk, files;
	unsigned int freesec, fpos, secnum;
	char* ptr = obuf;
	
	switch (mode) {
		case TYPE_SCL:
			files = obuf[8];
			if (files > 127) {
				printf("Too many files in image\n");
				break;
			}
			obuf[8]++;							// inc files count
			freesec = 9 + 14 * files;					// old catalog len
			memmove(obuf + freesec + 14, obuf + freesec, olen - freesec);	// free space for new dsc
			makedsc(obuf + freesec, fileName, iflen, seclen, isBasic);	// make new dsc
			memcpy(obuf + olen - 4 + 14, inbuf, seclen * 256);		// copy new data, erase old crc
			addcrc(obuf, olen - 4 + seclen * 256 + 14);			// create new crc
			savefile(aname, obuf, olen + seclen * 256 + 14);		// save all data
			break;
		case TYPE_TRD:
			files = obuf[0x8e4];
			if (files > 127) {
				printf("Too many files in image\n");
				break;
			}
			freesec = (obuf[0x8e5] & 0xff) | ((obuf[0x8e6] & 0xff) << 8);
			if (freesec < seclen) {
				printf("No room for file\n");
				break;
			}
			lastsec = obuf[0x8e1];
			lasttrk = obuf[0x8e2];
			files++;
			obuf[0x8e4] = files;
			freesec -= seclen;
			obuf[0x8e5] = freesec & 0xff;
			obuf[0x8e6] = ((freesec & 0xff00) >> 8);
			while (*ptr)				// find 1st free descriptor
				ptr += 16;
			makedsc(ptr, fileName, iflen, seclen, isBasic);
			ptr[14] = lastsec;
			ptr[15] = lasttrk;
			secnum = ((lasttrk << 4) + lastsec);	// free sector num
			fpos = (secnum << 8); 			// (lasttrk<<12)+(lastsec<<8);
			secnum += seclen;
			lastsec = secnum & 15;
			lasttrk = ((secnum & 0xfff0) >> 4);
			obuf[0x8e1] = lastsec;
			obuf[0x8e2] = lasttrk;
			memcpy(obuf + fpos, inbuf, dataLen);	// copy file data
			savefile(aname, obuf, 0xa0000);
			break;
		default:
			printf("Unknown image format : '%s'\n", aname);
			break;
	}
}

void tapAddBlock(FILE* file, int len, char* buf, int type) {
	int crc = type & 0xff;
	for (int i = 0; i < len; i++) {
		crc ^= buf[i];
	}
	fputc((len + 2) & 0xff, file);
	fputc(((len + 2) >> 8) & 0xff, file);
	fputc(type, file);
	fwrite(buf, len, 1, file);
	fputc(crc, file);
}

#pragma pack(push,1)

typedef struct {
	char type;
	char name[10];
	unsigned short dLen;
	unsigned short aStart;
	unsigned short pLen;
} tHead;

#pragma pack(pop)

void addtotap(char* fileName, char* aname, int isBasic, int autoStart, int headLess) {
	char fbuf[0x10000];
	int flen = readfile(fileName, fbuf, 0xfffd);
	if (flen == -1) {
		printf("Can't read input file\n");
		return;
	} else if (flen == 0) {
		printf("Input file '%s' is too long (0xfffd is a maximum)\n",fileName);
		return;
	}
	FILE* file = fopen(aname, "ab");
	if (!file) {
		printf("Can't open '%s' for append\n",aname);
	}
	
	if (!headLess) {
		tHead hd;
		memset(hd.name, 0x20, 10);
		xName nm = cutName(fileName);
		memcpy(hd.name, nm.name, 10);
		hd.dLen = flen;
		if (isBasic) {
			hd.type = 0x00;
			hd.aStart = autoStart;
			hd.pLen = flen;
		} else {
			hd.type = 0x03;
			hd.aStart = 0;
			hd.pLen = 0x8000;
		}
/*
		hd.dLen = htole16(hd.dLen);
		hd.aStart = htole16(hd.aStart);
		hd.pLen = htole16(hd.pLen);
*/
		tapAddBlock(file, sizeof(tHead), (char*)&hd, 0x00);
	}
	tapAddBlock(file, flen, fbuf, 0xff);		// data
	fclose(file);
}

void extract(char* fextra, char* aname) {
	int felen = strlen(fextra);
	if (felen > 10) {
		printf("Filename is too long ('filename.C' is maximum)\n");
		return;
	}
	if (felen < 2) {
		printf("Filename is too short (must be '.C' at least)\n");
		return;
	}
	if (fextra[felen - 2] != '.') {
		printf("Filename must be in 'fileneme.e' format\n");
		return;
	}
	
	char fname[9];
	memset(fname,0x20,9);
	memcpy(fname,fextra,felen-2);
	fname[8] = fextra[felen-1];
	
	char buf[0xa0000];
	int len=readfile(aname,buf,0xa0000);
	if (len < 1) {
		printf("Can't read file '%s'\n",aname);
		return;
	}
	int mode = testsig(buf, len);
	unsigned char* ptr = (unsigned char*)buf;
	int i = 0;
	int fpos;
	switch (mode) {
		case TYPE_SCL:
			ptr += 9;
			fpos = 9 + buf[8] * 14;		// begin of data
			while (i < buf[8]) {
				if (strncmp(fname, (char*)ptr, 9) == 0) {
					extractfile(buf, ptr, fpos, fextra);
				}
				fpos += (ptr[13] << 8);
				ptr += 14;
				i++;
			}
			break;
		case TYPE_TRD:
			while(*ptr && (i < 128)) {
				if (strncmp(fname, (char*)ptr, 9) == 0) {
					fpos=(ptr[15] << 12) + (ptr[14] << 8);	// position of begin of file in buf
					extractfile(buf, ptr, fpos, fextra);
				}
				ptr += 16;
				i++;
			}
			break;
		default:
			printf("Unknown image format\n");
			break;
	}
}

void list(char* fname) {
	char buf[0xa0000];
	int len = readfile(fname, buf,0xa0000);
	if (len < 1) {
		printf("Can't read file '%s'\n",fname);
		return;
	}
	int mode = testsig(buf, len);
	unsigned char* ptr = (unsigned char*)buf;
	unsigned char i = 0;
	int start;
	switch (mode) {
		case TYPE_SCL:
			ptr += 9;
			printf("Name\t\tExt\tStart\tSize\tSLen\n---------------------------\n");
			while (i < buf[8]) {
				start = ptr[9] | (ptr[10] << 8);
				len = ptr[11] | (ptr[12] << 8);
				printf("%.8s\t%c\t%i\t%i\t%i\n",ptr,ptr[8], start, len, ptr[13]);
				ptr+=14;
				i++;
			}
			break;
		case TYPE_TRD:
			printf("Name\t\tExt\tStart\tSize\tSLen\tSec\tTrk\n---------------------------\n");
			while (*ptr && (i < 128)) {
				if (*ptr != 1) {
					start = ptr[9] | (ptr[10] << 8);
					len = ptr[11] | (ptr[12] << 8);
					printf("%.8s\t%c\t%i\t%i\t%i\t%i\t%i\n",ptr,ptr[8],start,len,ptr[13],ptr[14],ptr[15]);
				}
				ptr+=16; i++;
			}
			break;
		default:
			printf("Unknown image format\n");
			break;
	}
}

void createtrd(char* fname) {
	char buf[0xa0000];
	memset(buf, 0x00, 0xa0000);
	buf[0x8e2] = 0x01;
	buf[0x8e3] = 0x16;
	buf[0x8e5] = 0xf0;
	buf[0x8e6] = 0x09;
	buf[0x8e7] = 0x10;
	FILE *ofile = fopen(fname,"wb");
	if (!ofile) {
		printf("Can't write to file '%s'\n",fname);
	} else {
		fwrite(buf,0xa0000,1,ofile);
		fclose(ofile);
	}
}

void createscl(char* fname) {
	char data[] = {'S', 'I', 'N', 'C', 'L', 'A', 'I', 'R', 0, 0, 0, 0, 0};
	addcrc(data, 9);
	savefile(fname, data, sizeof(data));
}

void createtap(char* fname) {
	savefile(fname, NULL, 0);
}

void help() {
	printf("::: Usage :::\n");
	printf("mctrd [-b][-a num] command file1 [file2]\n");
	printf("::: Keys :::\n");
	printf("%*s %s\n",-25,"--basic | -b","add file to archive as basic");
	printf("%*s %s\n",-25,"--autostart | -a NUM","set autostart line number for basic file");
	printf("::: Commands :::\n");
	printf("%*s %s\n",-25,"list image.trd","show image catalog");
	printf("%*s %s\n",-25,"ctrd image.trd","create new TRD file");
	printf("%*s %s\n",-25,"cscl image.scl","create new SCL file");
	printf("%*s %s\n",-25,"add file.ext image.trd","put file into image");
	printf("%*s %s\n",-25,"pop file.C image.trd","extract file from image");
}

int main(int ac,char* av[]) {
	char* com = NULL;
	char* fname1 = NULL;
	char* fname2 = NULL;
	int isBasic = 0;
	int autoStart = 0;
	int headLess = 0;
	int i = 1;
	char* parg;
	while (i < ac) {
		parg = av[i++];
		if ((strcmp(parg,"-a") == 0) || (strcmp(parg,"--autostart") == 0)) {
			if (i < ac) {
				autoStart = atoi(av[i++]);
			} else {
				printf("Invalid argument count\n");
				return 1;
			}
		} else if ((strcmp(parg,"-b") == 0) || (strcmp(parg,"--basic") == 0)) {
			isBasic = 1;
		} else if ((strcmp(parg,"-h") == 0) || (strcmp(parg,"--help") == 0)) {
			help();
			return 0;
		} else if ((strcmp(parg,"-n") && strcmp(parg,"--no-head")) == 0) {
			headLess = 1;
		} else {
			if (!com) com = parg;
			else if (!fname1) fname1 = parg;
			else if (!fname2) fname2 = parg;
		}
	}
	if (!fname1) help();
	else if (strcmp(com,"list") == 0) list(fname1);
	else if (strcmp(com,"ctrd") == 0) createtrd(fname1);
	else if (strcmp(com,"cscl") == 0) createscl(fname1);
	else if (strcmp(com,"ctap") == 0) createtap(fname1);
	else if (!fname2) help();
	else if (strcmp(com,"pop") == 0) extract(fname1,fname2);
	else if (strcmp(com,"add") == 0) pack(fname1,fname2,isBasic,autoStart);
	else if (strcmp(com,"atap") == 0) addtotap(fname1, fname2, isBasic, autoStart, headLess);
	else help();
	return 0;
}
