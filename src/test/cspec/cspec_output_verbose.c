/*
 *  cspec_output_verbose.c   :  Verbose output with color (green for OK, red for fail and yellow for pending)
 *
 * See copyright notice in cspec.h
 *
 */

#include <stdarg.h>
#include <stdio.h>
#ifdef _WIN32
#	include <windows.h>
#endif
#include "cspec_output_verbose.h"

static CSpecOutputStruct verbose;

/* private functions */
static void coloredPrintf(CSpec_Color color, const char* format, ...);
#ifdef _WIN32
static WORD getWindowsColorAttribute(CSpec_Color color);
#else	/* !_WIN32 */
static int getAnsiColorCode(CSpec_Color color);
#endif	/* _WIN32 */


void startDescribeFunVerbose( const char *descr)
{
	printf("Describe:%s\n", descr);
}

void endDescribeFunVerbose( )
{
	printf("\n");
}

void startItFunVerbose( const char *descr)
{
	printf("   - it %s\n", descr);
}

void endItFunVerbose( )
{
	printf("\n");
}

void evalFunVerbose(const char*filename, int line_number, const char*assertion, int assertionResult)
{
	if(assertionResult)
	{
		coloredPrintf(CSPEC_COLOR_GREEN,
					"       OK: %s\n", assertion, filename, line_number);
	}
	else
	{
		coloredPrintf(CSPEC_COLOR_RED,
					"       Failed: %s in file %s at line %d\n", assertion, filename, line_number);
	}
}

void pendingFunVerbose(const char* reason)
{
	coloredPrintf(CSPEC_COLOR_YELLOW, "       Pending: %s\n", reason);
}

CSpecOutputStruct* CSpec_NewOutputVerbose()
{
	CSpec_InitOutput(&verbose);
	
	verbose.startDescribeFun	= startDescribeFunVerbose;
	verbose.endDescribeFun		= endDescribeFunVerbose;
	verbose.startItFun			= startItFunVerbose;
	verbose.endItFun			= endItFunVerbose;
	verbose.evalFun				= evalFunVerbose;
	verbose.pendingFun			= pendingFunVerbose;

	return &verbose;
}

#ifdef _WIN32
static WORD
getWindowsColorAttribute(CSpec_Color color)
{
	WORD color_attribute;


	switch(color)
	{
	case CSPEC_COLOR_RED:
		color_attribute = FOREGROUND_RED;
		break;
	case CSPEC_COLOR_GREEN:
		color_attribute = FOREGROUND_GREEN;
		break;
	case CSPEC_COLOR_YELLOW:
		color_attribute = FOREGROUND_GREEN | FOREGROUND_RED;
		break;
	default:
		color_attribute = 0;
		break;
	}

	return color_attribute;
}
#else	/* !_WIN32 */
static int
getAnsiColorCode(CSpec_Color color)
{
	int color_code;


	switch(color)
	{
	case CSPEC_COLOR_RED:
		color_code = 31;
		break;
	case CSPEC_COLOR_GREEN:
		color_code = 32;
		break;
	case CSPEC_COLOR_YELLOW:
		color_code = 33;
		break;
	default:
		color_code = 30;
		break;
	}

	return color_code;
}
#endif	/* _WIN32 */

static void
coloredPrintf(CSpec_Color color, const char* format, ...)
{
#ifdef _WIN32
	HANDLE console_handle;
	CONSOLE_SCREEN_BUFFER_INFO buffer_info;
	WORD default_color_attributes;
#endif	/* _WIN32 */
	va_list args;


	va_start(args, format);

#ifdef _WIN32

	console_handle = GetStdHandle(STD_OUTPUT_HANDLE);
	GetConsoleScreenBufferInfo(console_handle, &buffer_info);
	default_color_attributes = buffer_info.wAttributes;

	/* Set color */
	SetConsoleTextAttribute(console_handle,
							getWindowsColorAttribute(color) |
							FOREGROUND_INTENSITY);

	/* Print Text */
	vprintf(format, args);

	/* Reset color */
	SetConsoleTextAttribute(console_handle,
							default_color_attributes);

#else	/* !_WIN32 */

	/* Set color */
	printf("\033[0;%dm", getAnsiColorCode(color));

	/* Print Text */
	vprintf(format, args);

	/* Reset color */
	printf("\033[m");

#endif	/* _WIN32 */

	va_end(args);
	return;
}
