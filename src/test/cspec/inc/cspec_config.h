/*
 *  cspec_config.h   :  This file depends on the capabilities of your hardware/platform
 *
 * See copyright notice in cspec.h
 *
 */

#ifndef CSPEC_CONFIG_H
#define CSPEC_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

/* You can change cspec_double to an other type */
/* if your platform does not support it			*/
typedef double cspec_double;
cspec_double cspec_fabs( cspec_double arg );

int cspec_strcmp ( const char * str1, const char * str2 );

#ifdef __cplusplus
}
#endif

#endif

