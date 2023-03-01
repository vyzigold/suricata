#include "suricata-common.h" 
#include "util-unittest.h" 

#include "detect-parse.h" 
#include "detect-engine.h" 

#include "detect-helloworld.h"
#include <stdio.h>

/**
 * \brief Regex for parsing our keyword options
 */
#define PARSE_REGEX  "^\\s*([0-9]+)?\\s*,s*([0-9]+)?\\s*$" 


/* prototypes */
static int DetectHelloWorldMatch (ThreadVars *, DetectEngineThreadCtx *,
        Packet *, Signature *, SigMatch *);
static int DetectHelloWorldSetup (DetectEngineCtx *, Signature *, char *);
static void DetectHelloWorldFree (void *);
static void DetectHelloWorldRegisterTests (void);

uint32_t UTHSetIPv4Address(const char *str)
{
    struct in_addr in;
    if (inet_pton(AF_INET, str, &in) != 1) {
        printf("invalid IPv6 address %s\n", str);
        exit(EXIT_FAILURE);
    }
    return (uint32_t)in.s_addr;
}

/**
 * \brief Registration function for helloworld: keyword
 */
void DetectHelloWorldRegister(void) {
	fprintf(stderr, "register");
    sigmatch_table[DETECT_HELLOWORLD].name = "helloworld";
    sigmatch_table[DETECT_HELLOWORLD].desc = "<todo>";
    sigmatch_table[DETECT_HELLOWORLD].url = "<todo>";
    sigmatch_table[DETECT_HELLOWORLD].Match = DetectHelloWorldMatch;
    sigmatch_table[DETECT_HELLOWORLD].Setup = DetectHelloWorldSetup;
    sigmatch_table[DETECT_HELLOWORLD].Free = DetectHelloWorldFree;

    const char *eb;
    int eo;
    int opts = 0;

    return;

}


/**
 * \brief This function is used to match HELLOWORLD rule option on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch with context that we will cast into DetectHelloWorldData
 *
 * \retval 0 no match
 * \retval 1 match
 */
int DetectHelloWorldMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, SigMatch *m)
{
	fprintf(stderr, "match");
    int ret = 0;
    DetectHelloWorldData *helloworldd = (DetectHelloWorldData *) m->ctx;
	IPV4Hdr *ipv4h = malloc(sizeof(IPV4Hdr));
	memset(&ipv4h, 0, sizeof(IPV4Hdr));
	p->ip4h = &ipv4h;
	p->src.addr_data32[0] = UTHSetIPv4Address("4.3.2.1");
#if 0
    if (PKT_IS_PSEUDOPKT(p)) {
        /* fake pkt */
    }

    if (PKT_IS_IPV4(p)) {
        /* ipv4 pkt */
    } else if (PKT_IS_IPV6(p)) {
        /* ipv6 pkt */
    } else {
        SCLogDebug("pcket is of not IPv4 or IPv6");
        return ret;
    }
#endif
    /* packet payload access */
    if (p->payload != NULL && p->payload_len > 0) {
        if (helloworldd->helloworld1 == p->payload[0] &&
            helloworldd->helloworld2 == p->payload[p->payload_len - 1])
        {
            ret = 1;
        }
    }

    return ret;
}



/**
 * \brief This function is used to parse helloworld options passed via helloworld: keyword
 *
 * \param helloworldstr Pointer to the user provided helloworld options
 *
 * \retval helloworldd pointer to DetectHelloWorldData on success
 * \retval NULL on failure
 */

DetectHelloWorldData *DetectHelloWorldParse (char *helloworldstr)
{
	fprintf(stderr, "parse");
    DetectHelloWorldData *helloworldd = NULL;
    helloworldd = SCMalloc(sizeof (DetectHelloWorldData));
    helloworldd->helloworld1 = 1;
    helloworldd->helloworld2 = 2;

    return helloworldd;

}


/**
 * \brief this function is used to get the parsed helloworld data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param helloworldstr pointer to the user provided helloworld options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectHelloWorldSetup (DetectEngineCtx *de_ctx, Signature *s, char *helloworldstr)
{
	fprintf(stderr, "setup");
    DetectHelloWorldData *helloworldd = NULL;
    SigMatch *sm = NULL;

    helloworldd = DetectHelloWorldParse(helloworldstr);

    sm = SigMatchAlloc();

    sm->type = DETECT_HELLOWORLD;
    sm->ctx = (void *)helloworldd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}


/**
 * \brief this function will free memory associated with DetectHelloWorldData
 *
 * \param ptr pointer to DetectHelloWorldData
 */
void DetectHelloWorldFree(void *ptr) {
    DetectHelloWorldData *helloworldd = (DetectHelloWorldData *)ptr;
    SCFree(helloworldd);
}


void DetectHelloWorldRegisterTests(void) {
}



