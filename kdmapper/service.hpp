#pragma once
#include <Windows.h>
#include <string>
#include <filesystem>

namespace service
{
	bool RegisterAndStart(const std::string& driver_path);
	bool StopAndRemove(const std::string& driver_name);
};