/*
 *  cspec_private.h
 *
 * See copyright notice in cspec.h
 *
 */
#ifndef CSPEC_PRIVATE_H
#define CSPEC_PRIVATE_H

#ifdef __cplusplus
extern "C" {
#endif

int  CSpec_StartDescribe(const char *descr);
void CSpec_EndDescribe();

int  CSpec_StartIt(const char *descr);
void CSpec_EndIt();


void CSpec_Eval(const char*filename, int line_number, const char*assertion, int assertionResult);
void CSpec_Pending(const char* reason);

#ifdef __cplusplus
}
#endif

#define CSPEC_EVAL(x) 			{ CSpec_Eval(__FILE__, __LINE__, #x, (x)); }
#define CSPEC_PENDING(reason) 	{ CSpec_Pending(reason); }


#endif

