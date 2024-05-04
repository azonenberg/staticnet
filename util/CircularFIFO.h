/***********************************************************************************************************************
*                                                                                                                      *
* staticnet                                                                                                            *
*                                                                                                                      *
* Copyright (c) 2021-2024 Andrew D. Zonenberg and contributors                                                         *
* All rights reserved.                                                                                                 *
*                                                                                                                      *
* Redistribution and use in source and binary forms, with or without modification, are permitted provided that the     *
* following conditions are met:                                                                                        *
*                                                                                                                      *
*    * Redistributions of source code must retain the above copyright notice, this list of conditions, and the         *
*      following disclaimer.                                                                                           *
*                                                                                                                      *
*    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the       *
*      following disclaimer in the documentation and/or other materials provided with the distribution.                *
*                                                                                                                      *
*    * Neither the name of the author nor the names of any contributors may be used to endorse or promote products     *
*      derived from this software without specific prior written permission.                                           *
*                                                                                                                      *
* THIS SOFTWARE IS PROVIDED BY THE AUTHORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED   *
* TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL *
* THE AUTHORS BE HELD LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES        *
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR       *
* BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT *
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE       *
* POSSIBILITY OF SUCH DAMAGE.                                                                                          *
*                                                                                                                      *
***********************************************************************************************************************/

/**
	@file
	@brief Declaration of CircularFIFO
 */
#ifndef CircularFIFO_h
#define CircularFIFO_h

#include <stdio.h>
#include <stdlib.h>

/**
	@brief A circular buffer for storing byte-stream data which supports arbitrary length reads, writes, and peeks.

	Pointers are 16 bit to reduce the memory footprint. One extra bit is required to distinguish between
	empty and full positions so the maximum legal value for SIZE is 2^15-1.

	This class has no interlocks and is not thread/interrupt safe without external locks.
 */
template<uint16_t SIZE>
class CircularFIFO
{
public:
	CircularFIFO()
	{ Reset(); }

	/**
		@brief Clears the FIFO to an empty state
	 */
	void Reset()
	{
		m_readPtr = 0;
		m_writePtr = 0;
	}

	/**
		@brief Returns the number of bytes of data available to read
	 */
	uint16_t ReadSize()
	{ return (m_writePtr - m_readPtr) % SIZE; }

	/**
		@brief Returns the number of bytes of free buffer space
	 */
	uint16_t WriteSize()
	{ return SIZE - ReadSize(); }

	/**
		@brief Pushes a buffer of data into the FIFO

		Writes are all-or-nothing. If len > WriteSize() this function returns false and the FIFO state is unmodified.
	 */
	bool Push(const uint8_t* data, uint16_t len)
	{
		if(len > WriteSize())
			return false;

		//TODO: optimized version using memcpy
		//(note that we need to handle wraparound)
		for(uint16_t i=0; i<len; i++)
			Push(data[i]);
		return true;
	}

	/**
		@brief Pushes a single byte of data into the FIFO

		Returns true if there was a free byte or false if not.
	 */
	bool Push(uint8_t c)
	{
		if(WriteSize() == 0)
			return false;

		m_data[m_writePtr % SIZE] = c;
		m_writePtr = IncrementPointer(m_writePtr);
		return true;
	}

	/**
		@brief Pops a single byte of data from the FIFO
	 */
	uint8_t Pop()
	{
		if(ReadSize() == 0)
			return 0;

		uint8_t ret = m_data[m_readPtr % SIZE];
		m_readPtr = IncrementPointer(m_readPtr);

		//HACK: Reset pointers so they don't wrap
		if(m_readPtr == m_writePtr)
		{
			m_writePtr = 0;
			m_readPtr = 0;
		}

		return ret;
	}

	/**
		@brief Pops a block of data from the FIFO
	 */
	void Pop(uint16_t size)
	{
		//cap size
		if(size > ReadSize())
			size = ReadSize();

		//TODO: be efficient
		for(uint16_t i=0; i<size; i++)
			Pop();
	}

	/**
		@brief Rotates the buffer such that the read pointer is now at zero and returns a pointer to the data
	 */
	__attribute__((noinline))
	uint8_t* Rewind()
	{
		//Figure out how many spaces we need to rewind the buffer by
		uint16_t nbytes = ReadSize();

		//If we're already rewound, we're done already
		if(m_readPtr == 0)
			return m_data;

		//If empty, just reset pointers (no data to copy)
		else if(m_writePtr == m_readPtr)
		{}

		//Easy case: buffer hasn't wrapped past zero yet
		//Just move the data left in place
		else if(m_writePtr > m_readPtr)
			memmove(m_data, m_data + (m_readPtr % SIZE), nbytes);

		//Hard case: there's data where we want to go
		//TODO implement this (may need to iterate)
		else
		{
			while(1)
			{}
		}

		//Done
		m_readPtr = 0;
		m_writePtr = nbytes;
		return m_data;
	}

protected:

	/**
		@brief Increments a pointer mod our pointer size
	 */
	uint16_t IncrementPointer(uint16_t p)
	{ return (p + 1) % (2*SIZE); }

	uint16_t m_writePtr;
	uint16_t m_readPtr;
	uint8_t m_data[SIZE];
};

#endif
