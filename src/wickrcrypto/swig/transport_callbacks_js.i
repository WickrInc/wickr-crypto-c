%include "typemaps.i"

%{
using v8::Local;
using v8::MaybeLocal;
using v8::Persistent;
using v8::Object;
using v8::Isolate;
using v8::Number;
using v8::Function;
using v8::Value;
using v8::FunctionTemplate;
using v8::Maybe;

Local<Function> WickrTransportGetCallback(Isolate *isolate, const void *callbackObjectPtr, const char *name)
{
    Local<Object> jsCallbacks = Local<Object>::New(isolate, *(Persistent<Object> *)callbackObjectPtr);
    Local<v8::String> callbackProperty = v8::String::NewFromUtf8(isolate, name, v8::NewStringType::kNormal).ToLocalChecked();
    Local<Value> callbackValue = Local<Value>();

    if (!jsCallbacks->Get(isolate->GetCurrentContext(), callbackProperty).ToLocal(&callbackValue)) {
        return Local<Function>();
    }

    if (!callbackValue->IsFunction()) {
        return Local<Function>();
    }

    return Local<Function>::Cast(callbackValue);
}

MaybeLocal<Value> WickrTransportExecuteCallbackValue(Isolate *isolate,Local<Function>& callbackFunction, unsigned argc, Local<Value> *argv)
{
    return (*callbackFunction)->Call(isolate->GetCurrentContext(), Null(isolate), argc, argv);
}

void WickrTransportExecuteCallbackVoid(Isolate *isolate,Local<Function>& callbackFunction, unsigned argc, Local<Value> *argv)
{
    Local<Value> value;
    
    if (WickrTransportExecuteCallbackValue(isolate, callbackFunction, argc, argv).ToLocal(&value)) {
        if (!value->IsNullOrUndefined()) {
            printf("(wickr-crypto-c) Warning: Unexpected return from void callback function\n");
        }
    }
}

void WickrTransportTxCallback(const wickr_transport_ctx_t *ctx, wickr_buffer_t *data)
{
    Isolate *isolate = Isolate::GetCurrent();
    Local<Function> callbackFunction = WickrTransportGetCallback(isolate, wickr_transport_ctx_get_user_ctx(ctx), "onTx");

    if (callbackFunction.IsEmpty()) {
        return;
    }

    Local<Value> argv[] = {
        node::Buffer::Copy(isolate, (const char *)data->bytes, data->length).ToLocalChecked(),
    };

    wickr_buffer_destroy(&data);

    WickrTransportExecuteCallbackVoid(isolate, callbackFunction, 1, argv);
}

void WickrTransportRxCallback(const wickr_transport_ctx_t *ctx, wickr_buffer_t *data) 
{
    Isolate *isolate = Isolate::GetCurrent();
    Local<Function> callbackFunction = WickrTransportGetCallback(isolate, wickr_transport_ctx_get_user_ctx(ctx), "onRx");

    if (callbackFunction.IsEmpty()) {
        return;
    }

    Local<Value> argv[] = {
        node::Buffer::Copy(isolate, (const char *)data->bytes, data->length).ToLocalChecked(),
    };

    wickr_buffer_destroy(&data);

    WickrTransportExecuteCallbackVoid(isolate, callbackFunction, 1, argv);
}

void WickrTransportStateChangedCallback(const wickr_transport_ctx_t *ctx, wickr_transport_status status)
{
    Isolate *isolate = Isolate::GetCurrent();
    Local<Function> callbackFunction = WickrTransportGetCallback(isolate, wickr_transport_ctx_get_user_ctx(ctx), "onStateChanged");

    if (callbackFunction.IsEmpty()) {
        return;
    }

    Local<Value> argv[] = {
        Number::New(isolate, (double)status),
    };

    WickrTransportExecuteCallbackVoid(isolate, callbackFunction, 1, argv);
}

void WickrTransportIdentityValidationResponse(const v8::FunctionCallbackInfo<Value>& args)
{
    Local<Object> context = Local<Object>::Cast(args.Data());

    if (context.IsEmpty()) {
        SWIG_V8_Raise("Invalid Identity Validation Context Data");
    }

    MaybeLocal<Value> transportContext = context->Get(args.GetIsolate()->GetCurrentContext(), 0);

    if (transportContext.IsEmpty()) {
        SWIG_V8_Raise("Identity Validation Missing Transport Context");
    }

    MaybeLocal<Value> transportCallback = context->Get(args.GetIsolate()->GetCurrentContext(), 1);

    if (transportCallback.IsEmpty()) {
        SWIG_V8_Raise("Identity Validation Missing Transport Callback");
    }

    void *ctxVoid = 0;
    int convertResult = SWIG_ConvertPtr(transportContext.ToLocalChecked(), &ctxVoid, SWIGTYPE_p_wickr_transport_ctx, 0 |  0 );

    if (!SWIG_IsOK(convertResult)) {
        SWIG_V8_Raise("Identity Validation Invalid Transport Context Accessed");
    }

    void *callbackVoid = 0;
    convertResult = SWIG_ConvertFunctionPtr(transportCallback.ToLocalChecked(), &callbackVoid, SWIGTYPE_p_f_p_q_const__wickr_transport_ctx_p_wickr_identity_chain_p_f_p_q_const__wickr_transport_ctx_bool__void__void);

    if (!SWIG_IsOK(convertResult)) {
        SWIG_V8_Raise("Identity Validation Invalid Callback Function");
    }

    wickr_transport_ctx_t *transport_context = reinterpret_cast< wickr_transport_ctx_t * >(ctxVoid);
    wickr_transport_validate_identity_callback callback = (wickr_transport_validate_identity_callback)callbackVoid;

    if (args.Length() != 1) {
        SWIG_V8_Raise("Identity Validation Callback Missing Argument 0 (boolean)");
    }

#if (V8_MAJOR_VERSION-0) < 7
    callback(transport_context, args[0]->BooleanValue());
#else
    callback(transport_context, args[0]->BooleanValue(v8::Isolate::GetCurrent()));
#endif

}

void WickrTransportIdentityValidationCallback(const wickr_transport_ctx_t *ctx,
    wickr_identity_chain_t *identity, wickr_transport_validate_identity_callback callback)
{
    Isolate *isolate = Isolate::GetCurrent();
    Local<Function> callbackFunction = WickrTransportGetCallback(isolate, wickr_transport_ctx_get_user_ctx(ctx), "identityVerify");


    if (callbackFunction.IsEmpty()) {
        return callback(ctx, false);
    }

    Local<Object> context = Object::New(isolate);
    Maybe<bool> didSetTransport = context->Set(isolate->GetCurrentContext(), 0, SWIG_NewPointerObj(SWIG_as_voidptr(ctx), SWIGTYPE_p_wickr_transport_ctx, 0 |  0 ));
    Maybe<bool> didSetCallback = context->Set(isolate->GetCurrentContext(), 1,SWIG_NewFunctionPtrObj((void *)(callback), SWIGTYPE_p_f_p_q_const__wickr_transport_ctx_p_wickr_identity_chain_p_f_p_q_const__wickr_transport_ctx_bool__void__void));

    if (didSetTransport.IsNothing() || didSetCallback.IsNothing()) {
        SWIG_V8_Raise("Identity Validation Failed to Set Callback");
    }

    Local<FunctionTemplate> onCompleteTemplate = FunctionTemplate::New(isolate, WickrTransportIdentityValidationResponse, context);
    Local<Function> onComplete = onCompleteTemplate->GetFunction(isolate->GetCurrentContext()).ToLocalChecked();

    Local<Value> argv[] = {
        SWIG_NewPointerObj(SWIG_as_voidptr(identity), SWIGTYPE_p_wickr_identity_chain, SWIG_POINTER_OWN |  0),
        onComplete
    };

    WickrTransportExecuteCallbackVoid(isolate, callbackFunction, 2 , argv);
}

%}

%typemap(in) (wickr_transport_callbacks_t callbacks, void *user_data)
%{

$1 = {
    .tx = &WickrTransportTxCallback,
    .rx = &WickrTransportRxCallback,
    .on_state = &WickrTransportStateChangedCallback,
    .on_identity_verify = &WickrTransportIdentityValidationCallback,
};

$2 = new Persistent<Object>(Isolate::GetCurrent(), $input->ToObject(v8::Isolate::GetCurrent()));

%}