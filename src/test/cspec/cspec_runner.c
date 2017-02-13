/*
 *  cspec_runner.c   :  The runner
 *
 * TODO: What if fun or output are NULL? Should we set the output for each run?
 *
 * See copyright notice in cspec.h
 *
 */

#include "cspec.h"

int CSpec_Run( CSpecDescriptionFun fun, CSpecOutputStruct* output )
{
	CSpec_SetOutput(output);
	fun();
	return output->failed;
}

