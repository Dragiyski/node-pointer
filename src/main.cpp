#include <v8.h>
#include <node.h>
#include "js-helper.h"
#include "config.h"
#include <cstdint>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#ifdef HAVE_WINDOWS_H
#include <Windows.h>
#endif

void js_IsValidPointer(const v8::FunctionCallbackInfo<v8::Value> &info) {
    auto isolate = info.GetIsolate();
    v8::HandleScope scope(isolate);
    auto context = isolate->GetCurrentContext();
    if (info.Length() < 1) {
        JS_THROW_INVALID_ARG_COUNT(NOTHING, context, info, 1);
    }
    if (!info[0]->IsBigInt()) {
        JS_THROW_INVALID_ARG_TYPE(NOTHING, context, info, 0, "[bigint]");
    }
    bool lossless;
    auto ptrJsValue = info[0].As<v8::BigInt>()->Uint64Value(&lossless);
    if (!lossless || ptrJsValue > UINTPTR_MAX) {
        auto maxValue = v8::BigInt::NewFromUnsigned(isolate, UINTPTR_MAX);
        JS_EXECUTE_RETURN_HANDLE(NOTHING, v8::String, message, ToDetailString(context, "Pointer value overflow: ", info[0], " > ", maxValue.As<v8::Value>(), ""));
        isolate->ThrowException(v8::Exception::RangeError(message));
        return;
    }
    if (ptrJsValue == 0) {
        info.GetReturnValue().Set(false);
        return;
    }

#if defined(HAVE_MINCORE) && defined(HAVE_SYSCONF) && defined(HAVE_SYSCONF_SC_PAGESIZE)
    errno = 0;
    auto pageSize = sysconf(_SC_PAGESIZE);
    auto mask = ~(pageSize - 1);
    unsigned char ignored;
    info.GetReturnValue().Set(true);
    if (mincore(reinterpret_cast<void *>(ptrJsValue & mask), pageSize, &ignored) < 0) {
        if (errno != ENOMEM) {
            JS_EXECUTE_RETURN_HANDLE(NOTHING, v8::String, message, ToDetailString(context, "Unable to validate pointer value"));
            isolate->ThrowException(v8::Exception::Error(message));
            return;
        }
        info.GetReturnValue().Set(false);
    }
#elif defined(HAVE_VIRTUAL_QUERY)
    JS_EXECUTE_RETURN_HANDLE(NOTHING, v8::String, message, ToDetailString(context, "[Win32]: Not implemented"));
    isolate->ThrowException(v8::Exception::Error(message));
    return;
#else
#error The current platform is missing required features
#endif
}

NODE_MODULE_INIT() {
    v8::Isolate *isolate = context->GetIsolate();
    v8::HandleScope scope(isolate);
    {
        auto value = v8::BigInt::NewFromUnsigned(isolate, UINTPTR_MAX);
        JS_EXECUTE_RETURN_HANDLE(NOTHING, v8::String, name, ToString(context, "UINTPTR_MAX"));
        JS_EXECUTE_IGNORE(NOTHING, exports->DefineOwnProperty(context, name, value, JS_PROPERTY_ATTRIBUTE_CONSTANT));
    }
    {
        auto value = v8::BigInt::New(isolate, INTPTR_MAX);
        JS_EXECUTE_RETURN_HANDLE(NOTHING, v8::String, name, ToString(context, "INTPTR_MAX"));
        JS_EXECUTE_IGNORE(NOTHING, exports->DefineOwnProperty(context, name, value, JS_PROPERTY_ATTRIBUTE_CONSTANT));
    }
    {
        auto value = v8::BigInt::New(isolate, INTPTR_MIN);
        JS_EXECUTE_RETURN_HANDLE(NOTHING, v8::String, name, ToString(context, "INTPTR_MIN"));
        JS_EXECUTE_IGNORE(NOTHING, exports->DefineOwnProperty(context, name, value, JS_PROPERTY_ATTRIBUTE_CONSTANT));
    }
    {
        JS_EXECUTE_RETURN_HANDLE(NOTHING, v8::String, name, ToString(context, "isValidPointer"));
        JS_EXECUTE_RETURN_HANDLE(NOTHING, v8::Function, value, v8::Function::New(context, js_IsValidPointer, exports, 1, v8::ConstructorBehavior::kThrow));
        JS_EXECUTE_IGNORE(NOTHING, exports->DefineOwnProperty(context, name, value, JS_PROPERTY_ATTRIBUTE_FROZEN));
    }
}