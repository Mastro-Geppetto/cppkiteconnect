#pragma once

#include <string>
#include <exception>

namespace kite
{
	/*!
	Base exception class representing a Kite client exception.

	Every specific Kite client exception is a subclass of this
	and  exposes two instance variables "code" (HTTP error code)
	and "message" (error text).
	*/
	struct KiteException : public std::exception
	{
		std::string message;
		int code;

		KiteException(std::string mesg, int errCode = 500) : message(mesg), code(errCode)
		{	}

		virtual const char* what() const throw()
		{
			return message.c_str();
		}
	};

	class GeneralException : public KiteException
	{
		/*An unclassified, general error. Default code is 500.*/
	public:
		GeneralException(std::string mesg, int errCode = 500) : KiteException(mesg, errCode)
		{}
	};

	class TokenException : public KiteException
	{
		/*Represents all token and authentication related errors. Default code is 403.*/

	public:
		TokenException(std::string mesg, int errCode = 500) : KiteException(mesg, errCode)
		{}

	};

	class PermissionException : public KiteException
	{
		/*Represents permission denied exceptions for certain calls. Default code is 403."""*/

	public:
		PermissionException(std::string mesg, int errCode = 500) : KiteException(mesg, errCode)
		{}

	};

	class OrderException : public KiteException
	{
		/*Represents all order placement and manipulation errors. Default code is 500."""*/
	public:
		OrderException(std::string mesg, int errCode = 500) : KiteException(mesg, errCode)
		{}

	};


	class InputException : public KiteException
	{
		/*Represents user input errors such as missing and invalid parameters. Default code is 400."""*/
	public:
		InputException(std::string mesg, int errCode = 500) : KiteException(mesg, errCode)
		{}

	};


	class DataException : public KiteException
	{
		/*!
		@brief : Represents a bad response from the backend Order Management System (OMS).
				 Default code is 502 ( Bad Gateway ).
		*/
	public:
		DataException(std::string mesg, int errCode = 502) : KiteException(mesg, errCode)
		{}

	};


	class NetworkException : public KiteException
	{
		/*!
		@brief : Represents a network issue between Kite and the backend Order Management System (OMS).
		         Default code is 503 ( Service Unavailable ).
		*/
	public:
		NetworkException(std::string mesg, int errCode = 503) : KiteException(mesg, errCode)
		{}

	};

}