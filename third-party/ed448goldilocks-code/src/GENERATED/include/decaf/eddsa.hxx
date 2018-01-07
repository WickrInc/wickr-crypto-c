/**
 * @file decaf/eddsa.hxx
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * EdDSA crypto routines, metaheader.
 *
 * @warning This file was automatically generated in Python.
 * Please do not edit it.
 */

#ifndef __DECAF_EDDSA_HXX__
#define __DECAF_EDDSA_HXX__ 1

/** Namespace for all libdecaf C++ objects. */
namespace decaf {
    /** How signatures handle hashing. */
    enum Prehashed {
        PURE,     /**< Sign the message itself.  This can't be done in one pass. */
        PREHASHED /**< Sign the hash of the message. */
    };
}

#include <decaf/ed255.hxx>
#include <decaf/ed448.hxx>

#endif /* __DECAF_EDDSA_HXX__ */
