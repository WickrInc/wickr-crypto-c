/*
 *  cspec_output_unit.c   :  Unit test like
 *
 * See copyright notice in cspec.h
 *
 */

#include <stdio.h>
#include "cspec_output_unit.h"

typedef struct
{
	CSpecOutputStruct output;

	int nbPassed;
	int nbTotal;

} CSpecOutputUnitStruct;

static CSpecOutputUnitStruct unit;

void startDescribeFunUnit( const char *descr)
{
	printf("Unit testing: %s\n", descr);
	unit.nbPassed = 0;
	unit.nbTotal  = 0;
}

void endDescribeFunUnit( )
{
	if(unit.nbPassed == unit.nbTotal)
	{
		printf("\n\tAll tests Passed (%d)\n\n", unit.nbTotal);
	}
	else
	{
		printf("\n\tPassed %d tests out of %d\n\n", unit.nbPassed, unit.nbTotal);
	}
}

void evalFunUnit(const char*filename, int line_number, const char*assertion, int assertionResult)
{
	unit.nbTotal++;
	if(assertionResult)
	{
		unit.nbPassed++;
	}
	else
	{
		printf("\t:::Failed:::\t%s\n\t%s(%d)\n", assertion, filename, line_number);
	}
}

CSpecOutputStruct* CSpec_NewOutputUnit()
{
	CSpec_InitOutput(& (unit.output) );
	
	unit.output.startDescribeFun	= startDescribeFunUnit;
	unit.output.endDescribeFun		= endDescribeFunUnit;
	unit.output.startItFun			= 0;
	unit.output.endItFun			= 0;
	unit.output.evalFun				= evalFunUnit;
	unit.output.pendingFun			= 0;

	return &(unit.output);
}

