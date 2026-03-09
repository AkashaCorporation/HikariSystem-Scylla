/**
 * HexCore Rellic - N-API Wrapper Implementation (STUB)
 * Decompiles LLVM IR to pseudo-C via Rellic
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 *
 * This is a stub implementation. The real decompilation logic will be
 * implemented after the Rellic port to LLVM 18.1.8 is complete.
 */

#include "rellic_wrapper.h"

// ---------------------------------------------------------------------------
// RellicDecompiler
// ---------------------------------------------------------------------------

Napi::Object RellicDecompiler::Init(Napi::Env env, Napi::Object exports) {
	Napi::Function func = DefineClass(env, "RellicDecompiler", {
		InstanceMethod("decompile", &RellicDecompiler::Decompile),
		InstanceMethod("decompileAsync", &RellicDecompiler::DecompileAsync),
		InstanceMethod("close", &RellicDecompiler::Close),
		InstanceMethod("isOpen", &RellicDecompiler::IsOpen),
	});

	Napi::FunctionReference* constructor = new Napi::FunctionReference();
	*constructor = Napi::Persistent(func);
	env.SetInstanceData(constructor);

	exports.Set("RellicDecompiler", func);
	return exports;
}

RellicDecompiler::RellicDecompiler(const Napi::CallbackInfo& info)
	: Napi::ObjectWrap<RellicDecompiler>(info) {
	// STUB: LLVM context will be initialized when Rellic port is ready
	// llvmContext_ = std::make_unique<llvm::LLVMContext>();
}

RellicDecompiler::~RellicDecompiler() {
	closed_ = true;
	llvmContext_.reset();
}

Napi::Value RellicDecompiler::Decompile(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		DecompileResult result;
		result.success = false;
		result.error = "Decompiler is closed";
		result.functionCount = 0;
		return DecompileResultToJS(env, result);
	}

	if (info.Length() < 1 || !info[0].IsString()) {
		DecompileResult result;
		result.success = false;
		result.error = "Expected string argument (LLVM IR text)";
		result.functionCount = 0;
		return DecompileResultToJS(env, result);
	}

	std::string irText = info[0].As<Napi::String>().Utf8Value();

	try {
		DecompileResult result = DoDecompile(irText);
		return DecompileResultToJS(env, result);
	} catch (const std::exception& e) {
		DecompileResult result;
		result.success = false;
		result.error = std::string("Native exception: ") + e.what();
		result.functionCount = 0;
		return DecompileResultToJS(env, result);
	} catch (...) {
		DecompileResult result;
		result.success = false;
		result.error = "Unknown native exception";
		result.functionCount = 0;
		return DecompileResultToJS(env, result);
	}
}

Napi::Value RellicDecompiler::DecompileAsync(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		auto deferred = Napi::Promise::Deferred::New(env);
		DecompileResult result;
		result.success = false;
		result.error = "Decompiler is closed";
		result.functionCount = 0;
		deferred.Resolve(DecompileResultToJS(env, result));
		return deferred.Promise();
	}

	if (info.Length() < 1 || !info[0].IsString()) {
		auto deferred = Napi::Promise::Deferred::New(env);
		DecompileResult result;
		result.success = false;
		result.error = "Expected string argument (LLVM IR text)";
		result.functionCount = 0;
		deferred.Resolve(DecompileResultToJS(env, result));
		return deferred.Promise();
	}

	std::string irText = info[0].As<Napi::String>().Utf8Value();

	auto* worker = new DecompileAsyncWorker(env, this, std::move(irText));
	auto promise = worker->GetDeferred().Promise();
	worker->Queue();
	return promise;
}

Napi::Value RellicDecompiler::Close(const Napi::CallbackInfo& info) {
	if (!closed_) {
		closed_ = true;
		llvmContext_.reset();
	}
	return info.Env().Undefined();
}

Napi::Value RellicDecompiler::IsOpen(const Napi::CallbackInfo& info) {
	return Napi::Boolean::New(info.Env(), !closed_);
}

// ---------------------------------------------------------------------------
// Internal: DoDecompile (STUB)
// ---------------------------------------------------------------------------

DecompileResult RellicDecompiler::DoDecompile(const std::string& irText) {
	DecompileResult result;
	result.functionCount = 0;

	if (irText.empty()) {
		result.success = false;
		result.error = "Empty IR text";
		return result;
	}

	// STUB: Real implementation will:
	// 1. Parse IR with llvm::parseAssemblyString
	// 2. Run Rellic passes via new Pass Manager
	// 3. Generate Clang AST
	// 4. Simplify with Z3
	// 5. Print pseudo-C
	result.success = false;
	result.error = "Not implemented — Rellic port to LLVM 18 pending";
	return result;
}

Napi::Object RellicDecompiler::DecompileResultToJS(
	Napi::Env env, const DecompileResult& result) {

	Napi::Object obj = Napi::Object::New(env);
	obj.Set("success", Napi::Boolean::New(env, result.success));
	obj.Set("code", Napi::String::New(env, result.code));
	obj.Set("error", Napi::String::New(env, result.error));
	obj.Set("functionCount", Napi::Number::New(env, result.functionCount));
	return obj;
}

// ---------------------------------------------------------------------------
// DecompileAsyncWorker
// ---------------------------------------------------------------------------

DecompileAsyncWorker::DecompileAsyncWorker(
	Napi::Env env,
	RellicDecompiler* decompiler,
	std::string irText)
	: Napi::AsyncWorker(env),
	  decompiler_(decompiler),
	  irText_(std::move(irText)),
	  deferred_(Napi::Promise::Deferred::New(env)) {}

void DecompileAsyncWorker::Execute() {
	try {
		result_ = decompiler_->DoDecompile(irText_);
		if (!result_.success) {
			SetError(result_.error);
		}
	} catch (const std::exception& e) {
		result_.success = false;
		result_.error = std::string("Native exception during async decompile: ") + e.what();
		result_.functionCount = 0;
		SetError(result_.error);
	} catch (...) {
		result_.success = false;
		result_.error = "Unknown native exception during async decompile";
		result_.functionCount = 0;
		SetError(result_.error);
	}
}

void DecompileAsyncWorker::OnOK() {
	Napi::Env env = Env();
	deferred_.Resolve(decompiler_->DecompileResultToJS(env, result_));
}

void DecompileAsyncWorker::OnError(const Napi::Error& error) {
	// Even on error, resolve with the result object (not reject)
	// This matches the sync API behavior: always return DecompileResult
	Napi::Env env = Env();
	deferred_.Resolve(decompiler_->DecompileResultToJS(env, result_));
}
