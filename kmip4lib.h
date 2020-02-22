extern const char *my_object_type_string(enum object_type);
extern const char *my_key_format_type_string(enum key_format_type);
extern const char *my_key_compression_type_string(enum key_compression_type);
extern const char *my_cryptographic_algorithm_string(enum cryptographic_algorithm);
extern const char *my_attribute_type_string(enum attribute_type);
extern const char *my_cryptographic_usage_mask_string(char *, int, int32);
extern const char *my_attribute_value_string(char *, int, enum attribute_type, void *);
extern const char *my_decode_error_string(int);
extern const char *my_decode_result_status_enum(enum result_status);
extern std::ostream& operator<<(std::ostream &, KMIP *);
inline extern std::ostream& operator<<(std::ostream &out, KMIP &ctx) { return out << &ctx; }
