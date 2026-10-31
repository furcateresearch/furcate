set(req fl_core fl_models fl_sense fl_nicla nvs_flash esp_system)
if(IDF_TARGET STREQUAL "esp32p4")
    list(APPEND req fl_spool)
endif()
idf_component_register(SRCS "main.c"
                       REQUIRES ${req})
