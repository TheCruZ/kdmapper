#pragma once
#include <string>

namespace service
{
	bool RegisterAndStart(const std::wstring& driver_path, const std::wstring& serviceName);
	bool StopAndRemove(const std::wstring& serviceName);
};