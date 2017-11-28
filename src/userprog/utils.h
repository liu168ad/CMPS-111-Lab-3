/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   utils.h
 * Author: pintos
 *
 * Created on November 27, 2017, 7:43 PM
 */

#ifndef UTILS_H
#define UTILS_H

#include "threads/semaphore.h"

struct aux
{
    char *cmdline_copy;
    struct semaphore sema;
    bool initialized;
};


#endif /* UTILS_H */

