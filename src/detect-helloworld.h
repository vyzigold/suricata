#ifndef _DETECT_HELLOWORLD_H
#define _DETECT_HELLOWORLD_H

typedef struct DetectHelloWorldData_ {
    uint8_t helloworld1;   /**< first value */
    uint8_t helloworld2;   /**< second value */
} DetectHelloWorldData;

void DetectHelloWorldRegister(void);

#endif  /* _DETECT_HELLOWORLD_H */
