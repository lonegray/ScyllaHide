#pragma once

#include <Windows.h>
#include <utility>

namespace scl
{
    class Handle
    {
    public:
        explicit Handle(HANDLE handle) : handle_(handle) {}
        ~Handle()
        {
            if (handle_ && (handle_ != INVALID_HANDLE_VALUE))
                CloseHandle(handle_);
        }

        Handle(const Handle &other) = delete;
        Handle &operator=(const Handle &other) = delete;

        HANDLE get() const { return handle_; }

    private:
        HANDLE handle_;
    };

    class VirtualMemoryHandle
    {
    public:
        explicit VirtualMemoryHandle(HANDLE hProcess, void *address) : process_(hProcess), address_(address) {}
        ~VirtualMemoryHandle()
        {
            if (process_ && address_)
                VirtualFree(process_, 0, MEM_RELEASE);
        }

        VirtualMemoryHandle(const VirtualMemoryHandle &other) = delete;
        VirtualMemoryHandle &operator=(const VirtualMemoryHandle &other) = delete;

        void *get() const { return address_; }
        std::pair<HANDLE, void*> reset(HANDLE hProcess, void *address)
        {
            auto ret = std::make_pair(process_, address_);
            process_ = hProcess;
            address_ = address;
            return ret;
        }

    private:
        HANDLE process_;
        void *address_;
    };
}
