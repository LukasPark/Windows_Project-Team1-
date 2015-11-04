#define TEXT_SECTION		0x01
#define DATA_SECTION		0x02
#define IDATA_SECTION	0x04
#define RSRC_SECTION		0x08
#define RELOC_SECTION	0x10
#define PE_HEADERS		0x20
#define ALL_SECTION		0x3f

typedef struct PATTERNS
{
	UCHAR* patterns;
	int pattern_type;
	int pattern_size;
	PATTERNS* next;
} PATTERNS;

typedef struct FOUND_PATTERN
{
	int found_loc;
	int pattern_size;
	UCHAR* patterns;
} FOUND_PATTERN;