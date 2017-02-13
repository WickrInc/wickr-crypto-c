/*
 *  cspec_output_xml.c   :  Xml output
 *
 * See copyright notice in cspec.h
 *
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "cspec_output_xml.h"

static CSpecOutputStruct xml;
static FILE *outputXmlFile = NULL;


void CSpec_XmlFileOpen(const char *filename, const char *encoding)
{
	time_t	timeValue;
	char*	timeStr;

    outputXmlFile = fopen(filename, "w");

	if (outputXmlFile == NULL)
	{
		return;
	}

	time(&timeValue);
	timeStr = ctime(&timeValue);
	timeStr[strlen(timeStr) - 1] = '\0';

	fprintf(outputXmlFile, "<?xml version=\"1.0\" encoding=\"%s\" ?>\n", encoding);
	fprintf(outputXmlFile, "<?xml-stylesheet type=\"text/xsl\" href=\"CSpec-Run.xsl\" ?>\n");
	fprintf(outputXmlFile, "<BEHAVIOUR timestump=\"%s\">\n", timeStr);
}

void CSpec_XmlFileClose(void)
{
	if (outputXmlFile == NULL)
	{
		return;
	}

	fprintf(outputXmlFile, "</BEHAVIOUR>\n");

	fclose(outputXmlFile);
}


void startDescribeFunXml(const char *descr)
{
	if (outputXmlFile == NULL)
	{
		return;
	}

	fprintf(outputXmlFile, "  <DESCRIBE>\n");
	fprintf(outputXmlFile, "    <DESCRIPTION><![CDATA[%s]]></DESCRIPTION>\n", descr);
}

void endDescribeFunXml(void)
{
	if (outputXmlFile == NULL)
	{
		return;
	}

	fprintf(outputXmlFile, "  </DESCRIBE>\n");
}

void startItFunXml(const char *descr)
{
	if (outputXmlFile == NULL)
	{
		return;
	}

	fprintf(outputXmlFile, "    <IT>\n");
	fprintf(outputXmlFile, "      <DESCRIPTION><![CDATA[it %s]]></DESCRIPTION>\n", descr);
}

void endItFunXml()
{
	if (outputXmlFile == NULL)
	{
		return;
	}

	fprintf(outputXmlFile, "    </IT>\n");
}

void evalFunXml(const char *filename, int line_number, const char *assertion, int assertionResult)
{
	if (outputXmlFile == NULL)
	{
		return;
	}

	if(assertionResult)
	{
		fprintf(outputXmlFile, "      <ASSERTION>\n");
		fprintf(outputXmlFile, "        <RESULT>OK</RESULT>\n");
		fprintf(outputXmlFile, "        <MESSAGE><![CDATA[%s]]></MESSAGE>\n", assertion);
		fprintf(outputXmlFile, "      </ASSERTION>\n");
	}
	else
	{
		fprintf(outputXmlFile, "      <ASSERTION>\n");
		fprintf(outputXmlFile, "        <RESULT>Failure</RESULT>\n");
		fprintf(outputXmlFile, "        <MESSAGE><![CDATA[%s in file %s at line %d]]></MESSAGE>\n", assertion, filename, line_number);
		fprintf(outputXmlFile, "      </ASSERTION>\n");
	}
}

void pendingFunXml(const char* reason)
{
	if (outputXmlFile == NULL)
	{
		return;
	}

	fprintf(outputXmlFile, "      <ASSERTION>\n");
	fprintf(outputXmlFile, "        <RESULT>Pending</RESULT>\n");
	fprintf(outputXmlFile, "        <MESSAGE><![CDATA[%s]]></MESSAGE>\n", reason);
	fprintf(outputXmlFile, "      </ASSERTION>\n");
}

CSpecOutputStruct* CSpec_NewOutputXml()
{
	CSpec_InitOutput(&xml);
	
	xml.startDescribeFun	= startDescribeFunXml;
	xml.endDescribeFun		= endDescribeFunXml;
	xml.startItFun			= startItFunXml;
	xml.endItFun			= endItFunXml;
	xml.evalFun				= evalFunXml;
	xml.pendingFun			= pendingFunXml;

	return &xml;
}

