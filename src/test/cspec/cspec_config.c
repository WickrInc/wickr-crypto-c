/*
 *  cspec_config.c   :  This file depends on the capabilities of your hardware/platform
 *
 * In case your platform does not support double or provides another function to compute the absolute
 * value of a double, you can customize in this file.
 *
 * TODO: add a comparison function for cspec_double
 *
 * See copyright notice in cspec.h
 *
 */

#include <string.h>
#include <math.h>

#include "cspec_config.h"

int cspec_strcmp ( const char * str1, const char * str2 )
{
	return strcmp(str1, str2);
}

cspec_double cspec_fabs( cspec_double arg )
{
	return fabs(arg);
}

