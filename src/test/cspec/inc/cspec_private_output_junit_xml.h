#ifndef CSPEC_PRIVATE_OUTPUT_XML_H
#define CSPEC_PRIVATE_OUTPUT_XML_H

#include "cspec_array.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char* message;
    const char* type;
    const char* fname;
    int line;
    const char* assertion_descr;
} failure_t;

typedef struct {
    int n_assert;
    int n_pending;
    char* descr;
    array_t* failures;
} itOutputs_t;

typedef struct {
    char* descr;
    int n_itOutputs;
    itOutputs_t* itOutputs;
} descrOutputs_t;

#define N_DESCRIBE 10
#define N_IT 10

/* private functions */
void startDescribeFunJUnitXml(const char *descr);
int startDescribeFunJUnitXml_expand_if_needed();
int startDescribeFunJUnitXml_init_descr(descrOutputs_t* const target_descr, const char* descr);
void endDescribeFunJUnitXml(void);
void startItFunJUnitXml(const char *descr);
int startItFunJUnitXml_expand_if_needed(descrOutputs_t* const target_descr);
int startItFunJUnitXml_init_it(descrOutputs_t* const target_descr, const char* const descr);
int startItFunJUnitXml_set_descr(itOutputs_t* const target_it, const char* const descr);
int startItFunJUnitXml_set_failure(itOutputs_t* const target_it);
void endItFunJUnitXml();
void evalFunJUnitXml(const char *filename, int line_number, const char *assertion, int assertionResult);
void pendingFunJUnitXml(const char* reason);

void output_header(const char *encoding);
void output_footer();
void output_describe();
void output_describe_header(const descrOutputs_t* const descr);
void output_describe_main(const descrOutputs_t* const descr);
void output_describe_footer();
void output_it(const itOutputs_t* const it);
void output_it_header(const itOutputs_t* const it);
void output_it_main(const itOutputs_t* const it);
void output_it_footer();
int sumup_failure(const descrOutputs_t* const p);
void destruct();
void destruct_descr(descrOutputs_t* const descr);
void destruct_it(itOutputs_t* const it);
void xml_file_close();

#ifdef __cplusplus
}
#endif

#endif
