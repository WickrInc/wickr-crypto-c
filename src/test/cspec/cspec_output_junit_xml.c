/*
 *  cspec_output_junit_xml.c   :  JUnit Xml output
 *
 * See copyright notice in cspec.h
 *
 */
#include <stdio.h>
#include <stdlib.h>                     /* realloc, free */
#include <string.h>                     /* strdup */
#include "cspec_output_junit_xml.h"
#include "cspec_private_output_junit_xml.h"

static CSpecOutputStruct xml;
static FILE *outputXmlFile = NULL;

static int n_descrOutputs;
static descrOutputs_t* descrOutputs;

static const char* const g_failure_message = "Failed";
static const char* const g_failure_type = "";

void CSpec_JUnitXmlFileOpen(const char *filename, const char *encoding)
{
	outputXmlFile = fopen(filename, "w");

	if (outputXmlFile == NULL)
	{
		return;
	}

	n_descrOutputs = 0;
	descrOutputs = NULL;

	output_header(encoding);
}

void CSpec_JUnitXmlFileClose(void)
{
	if (outputXmlFile == NULL)
	{
		return;
	}

    output_describe();
	output_footer();

    destruct();

    xml_file_close();
}

void output_header(const char *encoding)
{
    fprintf(outputXmlFile, "<?xml version=\"1.0\" encoding=\"%s\" ?>\n", encoding);
    fprintf(outputXmlFile, "<testsuites>\n");
}
void output_footer()
{
    fprintf(outputXmlFile, "</testsuites>\n");
}
void output_describe()
{
    int i;

	for (i = 0; i < n_descrOutputs; ++i) {
        output_describe_header(descrOutputs + i);
        output_describe_main(descrOutputs + i);
        output_describe_footer();
	}
}
void output_describe_header(const descrOutputs_t* const descr)
{
    int n_failure = sumup_failure(descr);
    fprintf(outputXmlFile,
            "  <testsuite errors=\"0\" failures=\"%d\" name=\"%s\" tests=\"%d\">\n",
            n_failure,
            descr->descr,
            descr->n_itOutputs);
}
void output_describe_main(const descrOutputs_t* const descr)
{
    int j;

    for (j = 0; j < descr->n_itOutputs; ++j) {
        output_it(descr->itOutputs + j);
    }
}
void output_describe_footer()
{
    fprintf(outputXmlFile, "  </testsuite>\n");
}
int sumup_failure(const descrOutputs_t* const descr)
{
    int j;
    int sum = 0;

    for (j = 0; j < descr->n_itOutputs; ++j) {
        sum += descr->itOutputs[j].failures->size;
    }
    return sum;
}
void output_it(const itOutputs_t* const it)
{
    output_it_header(it);
    output_it_main(it);
    output_it_footer();
}
void output_it_header(const itOutputs_t* const it)
{
    fprintf(outputXmlFile,
            "    <testcase name=\"%s\" assertions=\"%d\">\n",
            it->descr,
            it->n_assert - it->n_pending);
}
void output_it_main(const itOutputs_t* const it)
{
    size_t k;

    for (k = 0; k < it->failures->size; ++k) {
        const failure_t* const fail = array_get_element(it->failures, k);
        if (NULL == fail) {
            fprintf(stderr, "[ERR] %s(%d) array_get_element(%p, %d) returns NULL\n", __FILE__, __LINE__, it->failures, (int) k);
            destruct();
            xml_file_close();
            return;
        }

        fprintf(outputXmlFile,
                "      <failure message=\"%s\" type=\"%s\">\n",
                fail->message,
                fail->type);
        fprintf(outputXmlFile,
                "%s:%d: %s\n",
                fail->fname,
                fail->line,
                fail->assertion_descr);
        fprintf(outputXmlFile, "      </failure>\n");
    }
}
void output_it_footer()
{
    fprintf(outputXmlFile, "    </testcase>\n");
}

void destruct()
{
    int i;

    for (i = 0; i < n_descrOutputs; ++i) {
        destruct_descr(descrOutputs + i);
    }
	free(descrOutputs);
	descrOutputs = NULL;
}
void destruct_descr(descrOutputs_t* const descr)
{
    int j;

    if (NULL == descr) {
        return;
    }
    if (NULL != descr->descr) {
        free(descr->descr);
        descr->descr = NULL;
    }
    if (NULL != descr->itOutputs) {
        for (j = 0; j < descr->n_itOutputs; ++j) {
            destruct_it(descr->itOutputs + j);
        }
        free(descr->itOutputs);
        descr->itOutputs = NULL;
    }
    descr->n_itOutputs = 0;
}
void destruct_it(itOutputs_t* const it)
{
    if (NULL == it) {
        return;
    }
    if (NULL != it->descr) {
        free(it->descr);
        it->descr = NULL;
    }
    array_delete(&(it->failures));
}
void xml_file_close()
{
	int ret = fclose(outputXmlFile);
    if (0 != ret) {
        fprintf(stderr, "[ERR] %s(%d) fclose() failed\n", __FILE__, __LINE__);
    }
    outputXmlFile = NULL;
}

void startDescribeFunJUnitXml(const char *descr)
{
    int ret;

	if (outputXmlFile == NULL)
	{
		return;
	}
    
    ret = startDescribeFunJUnitXml_expand_if_needed();
    if (0 != ret) {
        return;
    }

    ret = startDescribeFunJUnitXml_init_descr(descrOutputs + n_descrOutputs, descr);
    if (0 != ret) {
        return;
    }

	++n_descrOutputs;
}
int startDescribeFunJUnitXml_expand_if_needed()
{
	if (0 == (n_descrOutputs % N_DESCRIBE)) {
        descrOutputs_t* p = realloc(descrOutputs, (n_descrOutputs + N_DESCRIBE) * sizeof(descrOutputs_t));
        if (NULL == p) {
            fprintf(stderr, "[ERR] %s(%d) realloc(%d * %d) failed\n", __FILE__, __LINE__,
                    n_descrOutputs + N_DESCRIBE,
                    (int) sizeof(descrOutputs_t));
            destruct();
            xml_file_close();
            return -1;
        }
        descrOutputs = p;
	}
    return 0;
}
int startDescribeFunJUnitXml_init_descr(descrOutputs_t* const target_descr, const char* descr)
{
	target_descr->descr = strdup(descr);
	target_descr->n_itOutputs = 0;
	target_descr->itOutputs = NULL;
    return 0;
}
void endDescribeFunJUnitXml(void)
{
}

void startItFunJUnitXml(const char *descr)
{
    descrOutputs_t* target_descr;
    int ret;

	if (outputXmlFile == NULL)
	{
		return;
	}

    target_descr = descrOutputs + (n_descrOutputs - 1);

    ret = startItFunJUnitXml_expand_if_needed(target_descr);
    if (0 != ret) {
        return;
    }

    ret = startItFunJUnitXml_init_it(target_descr, descr);
    if (0 != ret) {
        return;
    }

	++(target_descr->n_itOutputs);
}
int startItFunJUnitXml_expand_if_needed(descrOutputs_t* const target_descr)
{
	if (0 == (target_descr->n_itOutputs % N_IT)) {
        itOutputs_t* p = realloc(target_descr->itOutputs,
                                 (target_descr->n_itOutputs + N_IT) * sizeof(itOutputs_t));
        if (NULL == p) {
            fprintf(stderr, "[ERR] %s(%d) realloc(%d * %d) failed\n", __FILE__, __LINE__,
                    target_descr->n_itOutputs + N_IT,
                    (int) sizeof(itOutputs_t));
            destruct();
            xml_file_close();
            return -1;
        }
        target_descr->itOutputs = p;
	}
    return 0;
}
int startItFunJUnitXml_init_it(descrOutputs_t* const target_descr, const char* const descr)
{
    int ret;
    itOutputs_t* target_it = target_descr->itOutputs + target_descr->n_itOutputs;

    target_it->n_assert = 0;
	target_it->n_pending = 0;
    ret = startItFunJUnitXml_set_descr(target_it, descr);
    if (0 != ret) {
        return -1;
    }
    ret = startItFunJUnitXml_set_failure(target_it);
    if (0 != ret) {
        return -2;
    }
    return 0;
}
int startItFunJUnitXml_set_descr(itOutputs_t* const target_it, const char* const descr)
{
	target_it->descr = strdup(descr);
    if (NULL == target_it->descr) {
        fprintf(stderr, "[ERR] %s(%d) strdup(%p) failed\n", __FILE__, __LINE__, descr);
        destruct();
        xml_file_close();
        return -1;
    }
    return 0;
}
int startItFunJUnitXml_set_failure(itOutputs_t* const target_it)
{
	target_it->failures = array_new(sizeof(failure_t));
    if (NULL == target_it->failures) {
        fprintf(stderr, "[ERR] %s(%d) array_new(%d) failed\n", __FILE__, __LINE__, (int) sizeof(failure_t));
        destruct();
        xml_file_close();
        return -1;
    }
    return 0;
}

void endItFunJUnitXml()
{
}

void evalFunJUnitXml(const char *filename, int line_number, const char *assertion, int assertionResult)
{
	if (outputXmlFile == NULL)
	{
		return;
	}

	++(descrOutputs[n_descrOutputs - 1].itOutputs[descrOutputs[n_descrOutputs - 1].n_itOutputs - 1].n_assert);

	if(! assertionResult)
	{
        failure_t failure;
        int ret;

        failure.message = g_failure_message;
        failure.type = g_failure_type;
        failure.fname = filename;
        failure.line = line_number;
        failure.assertion_descr = assertion;
        ret = array_add(descrOutputs[n_descrOutputs - 1].itOutputs[descrOutputs[n_descrOutputs - 1].n_itOutputs - 1].failures, &failure);
        if (0 != ret) {
            fprintf(stderr, "[ERR] %s(%d) array_add() failed (ret=%d,descrOutputs=%p,n_descrOutputs=%d,itOutputs=%p,n_itOutputs=%d,failures=%p)\n",
                    __FILE__,
                    __LINE__,
                    ret,
                    descrOutputs,
                    n_descrOutputs,
                    descrOutputs[n_descrOutputs - 1].itOutputs,
                    descrOutputs[n_descrOutputs - 1].n_itOutputs,
                    descrOutputs[n_descrOutputs - 1].itOutputs[descrOutputs[n_descrOutputs - 1].n_itOutputs - 1].failures);
            destruct();
            xml_file_close();
        }
	}
}

void pendingFunJUnitXml(const char* reason)
{
	if (outputXmlFile == NULL)
	{
		return;
	}

	++(descrOutputs[n_descrOutputs - 1].itOutputs[descrOutputs[n_descrOutputs - 1].n_itOutputs - 1].n_pending);
}

CSpecOutputStruct* CSpec_NewOutputJUnitXml()
{
	CSpec_InitOutput(&xml);
	
	xml.startDescribeFun	= startDescribeFunJUnitXml;
	xml.endDescribeFun		= endDescribeFunJUnitXml;
	xml.startItFun			= startItFunJUnitXml;
	xml.endItFun			= endItFunJUnitXml;
	xml.evalFun				= evalFunJUnitXml;
	xml.pendingFun			= pendingFunJUnitXml;

	return &xml;
}
