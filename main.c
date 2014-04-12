#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#define TYPE_UNKNOWN	0
#define	TYPE_SCL	1
#define	TYPE_TRD	2

int readfile(char* fname, char* buf, int maxlen) {
	FILE *infile = fopen(fname,"rb");
	if (!infile) return -1;		// failed to open file
	fseek(infile, 0, SEEK_END);
	int iflen = ftell(infile);
	rewind(infile);
	if (iflen <= maxlen) {
		fread(buf, 0xa0000, 1, infile);
	} else {
		iflen = 0;
	}
	fclose(infile);
	return iflen;
}

int savefile(char* fname, char* buf, int len) {
	FILE *file = fopen(fname, "wb");
	if (!file) return 0;
	fwrite(buf, len, 1, file);
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

void makedsc(char* ptr, char* fname, char fext, int len, unsigned char slen, int isBasic) {
	strncpy(ptr, fname, 8);		// filename
	ptr[8] = fext;			// ext
	ptr[11] = len & 0xff;		// length
	ptr[12] = ((len & 0xff00) >> 8);
	ptr[13] = slen;			// sectors lenght
	if (isBasic) {
		ptr[9] = ptr[11];
		ptr[10] = ptr[12];
	} else {
		ptr[9] = ptr[10] = 0;
	}
}

void pack(char* fextra, char* aname, int isBasic, int autoStart) {
	char fname[8];
	char fext;
	int fnsize = strlen(fextra);
	char* dotpos = strrchr(fextra,'.');	// locate last dot
	if (dotpos == NULL) {
		fext = 'C';
	} else if (dotpos[1] == 0x00) {
		fext = 'C';
		fnsize = dotpos - fextra;
	} else {
		fext = dotpos[1];
		fnsize = dotpos - fextra;
	}
	if (isBasic) fext = 'B';
	if (fnsize > 8) fnsize = 8;
	memset(fname, 0x20, 8);
	memcpy(fname, fextra, fnsize);
	
	char *inbuf = malloc(0xff04 * sizeof(char));
	int iflen = readfile(fextra, inbuf, 0xff00);
	if (iflen == -1) {
		printf("Can't read file '%s'\n",fextra);
		free(inbuf);
		return;
	}
	if (iflen == 0) {
		printf("Input file '%s' is too long (0xff00 is a maximum)\n",fextra);
		free(inbuf);
		return;
	}
	if (isBasic) {
		inbuf[iflen] = 0x80;
		inbuf[iflen+1] = 0xaa;
		inbuf[iflen+2] = autoStart & 0xff;
		inbuf[iflen+3] = ((autoStart & 0xff00) >> 8);
	}
	
	char *obuf = malloc(0xa0000 * sizeof(char));
	int olen = readfile(aname, obuf, 0xa0000);
	if (olen < 1) {
		printf("Can't read output file '%s'\n", aname);
		free(inbuf);
		free(obuf);
		return;
	}
	
	int mode = testsig(obuf, olen);
	int dataLen = iflen + (isBasic ? 4 : 0);	// 80 aa <autostart>
	unsigned char seclen = ((dataLen & 0xff00) >> 8) + ((dataLen & 0xff) ? 1 : 0);	// sectors len
	unsigned char lastsec, lasttrk, files;
	unsigned int freesec, fpos, secnum;
	char* ptr = obuf;
	char dsc[16];
	FILE *ofile;
	
	switch (mode) {
		case TYPE_SCL:
			files = obuf[8];
			if (files > 127) {
				printf("Too many files in image\n");
				break;
			}
			obuf[8]++;
			ofile = fopen(aname, "wb");
			if (!ofile) {
				printf("Can't write to file '%s'\n",aname);
				break;
			}
			freesec = 9 + 14 * files;			// old catalog len
			fwrite(obuf, freesec, 1, ofile);		// save old catalog
			makedsc(dsc, fname, fext, iflen, seclen, isBasic);	// make 14bytes-len descriptor
			fwrite(dsc ,14, 1, ofile);			// write it
			fwrite(obuf + freesec, olen-freesec, 1, ofile);	// write old data
			fwrite(inbuf, dataLen, 1, ofile);		// write new data ( +2 bytes for basic)
			if ((dataLen & 0xff) !=0)
				fwrite(inbuf,0x100 - (dataLen & 0xff), 1, ofile);	// write end of sector
				fclose(ofile);
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
			makedsc(ptr, fname, fext, iflen, seclen, isBasic);
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
			printf("Unknown image format\n");
			break;
	}
	free(inbuf);
	free(obuf);
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
	
	char *buf = malloc(0xa0000 * sizeof(char));
	int len=readfile(aname,buf,0xa0000);
	if (len < 1) {
		printf("Can't read file '%s'\n",aname);
		free(buf);
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
	free(buf);
}

void list(char* fname) {
	char *buf = malloc(0xa0000 * sizeof(char));
	int len = readfile(fname, buf,0xa0000);
	if (len < 1) {
		printf("Can't read file '%s'\n",fname);
		free(buf);
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
			printf("Name\t\tExt\tStart\tSize\tSLen\tTrk\tSec\n---------------------------\n");
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
	free(buf);
}

void createtrd(char* fname) {
	char *buf = malloc(0xa0000 * sizeof(char));
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
	free(buf);
}

void createscl(char* fname) {
	FILE *ofile = fopen(fname, "wb");
	if (!ofile) {
		printf("Can't write to file '%s'\n",fname);
	} else {
		fwrite("SINCLAIR", 8, 1, ofile);
		fputc(0x00, ofile);
		fclose(ofile);
	}
}

void help() {
	printf("::: Usage :::\n");
	printf("mctrd [-b][-a num] command file1 [file2]\n");
	printf("mctrd [-b][-a num] -c command -i image [-f file]\n");
	printf("::: Keys :::\n");
	printf("%*s %s\n",-10,"-b","add file to archive as basic");
	printf("%*s %s\n",-10,"-a NUM","set autostart line number for basic file");
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
	char* imgName = NULL;
	char* fleName = NULL;
	int isBasic = 0;
	int autoStart = 0;
	int c;
	while ((c = getopt(ac,av,"-a:bcifh")) != -1) {
		switch (c) {
			case 'a': autoStart = atoi(optarg); break;
			case 'b': isBasic = 1; break;
			case 'c': com = optarg; break;
			case 'i': imgName = optarg; break;
			case 'f': fleName = optarg; break;
			case 'h': help(); return 0;
			case 1:
				if (!com) com = optarg;
				else if (!fname1) fname1 = optarg;
				else if (!fname2) fname2 = optarg;
				break;
		}
	}
// BSD getopt doesn't parse free arguments, do it by myself
	while (optind < ac) {
		if (!com) com = av[optind];
		else if (!fname1) fname1 = av[optind];
		else if (!fname2) fname2 = av[optind];
		optind++;
	}
	if (imgName) fname1 = imgName;
	if (!fname1) help();
	else if (strcmp(com,"list") == 0) list(fname1);
	else if (strcmp(com,"ctrd") == 0) createtrd(fname1);
	else if (strcmp(com,"cscl") == 0) createscl(fname1);
	else {
		if (imgName) fname2 = imgName;
		if (fleName) fname1 = imgName;
		if (!fname1 || !fname2) help();
		else if (strcmp(com,"pop") == 0) extract(fname1,fname2);
		else if (strcmp(com,"add") == 0) pack(fname1,fname2,isBasic,autoStart);
		else help();
	}
	return 0;
}
