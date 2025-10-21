#pragma once
#include <string>
#include "nt.hpp"

namespace service
{
	NTSTATUS RegisterAndStart(const std::wstring& driver_path, const std::wstring& serviceName);
	NTSTATUS StopAndRemove(const std::wstring& serviceName);
};