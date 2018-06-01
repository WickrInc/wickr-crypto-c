%include "typemaps.i"

%typemap(in) const wickr_buffer_t * ( const wickr_buffer_t * )
%{
  wickr_buffer_t temp$argnum;

  #ifndef BUILDING_NODE_EXTENSION
    if (!$input->IsArrayBuffer()) {
      $1 = NULL;
    }
    else {
      v8::Local<v8::ArrayBuffer> buffer = v8::Local<v8::ArrayBuffer>::Cast($input);  
      temp$argnum.length = buffer->GetContents().ByteLength();
      temp$argnum.bytes = (uint8_t *)buffer->GetContents().Data();
      $1 = &temp$argnum;
    }
  #else
  
    if ($input->IsNull()) {
      $1 = NULL;
    }
    else {
      v8::Local<v8::Object> bufferObj = $input->ToObject();
      temp$argnum.length = node::Buffer::Length(bufferObj);
      temp$argnum.bytes = (uint8_t *)node::Buffer::Data(bufferObj);
      $1 = &temp$argnum;
    }
  
  #endif
  
%}

%typemap(in) wickr_buffer_t * ( wickr_buffer_t * )
%{

  #ifndef BUILDING_NODE_EXTENSION
    if (!$input->IsArrayBuffer()) {
      $1 = NULL;
    }
    else {
      v8::Local<v8::ArrayBuffer> buffer = v8::Local<v8::ArrayBuffer>::Cast($input);
      $1 = wickr_buffer_create((const uint8_t *)buffer->GetContents().Data(), buffer->GetContents().ByteLength());
    }
  #else
  {
    if ($input->IsNull()) {
      $1 = NULL;
    }
    else {
      v8::Local<v8::Object> bufferObj = $input->ToObject();
      $1 = wickr_buffer_create((const uint8_t *)node::Buffer::Data(bufferObj), node::Buffer::Length(bufferObj));
    }
  }
  #endif
  
%}

%typemap(out) wickr_buffer_t * 
%{
    if (!result) {
      jsresult = SWIGV8_NULL();
    }
    else {
      #ifndef BUILDING_NODE_EXTENSION
        v8::Handle<v8::ArrayBuffer> ab = v8::ArrayBuffer::New(v8::Isolate::GetCurrent(), result->length);
        memcpy(ab->GetContents().Data(), result->bytes, result->length);
        jsresult = ab;
      #else
        v8::MaybeLocal<v8::Object> nodeBuffer = node::Buffer::Copy(v8::Isolate::GetCurrent(), (const char *)result->bytes, result->length);
        jsresult = nodeBuffer.ToLocalChecked();
      #endif

    }
    
%}