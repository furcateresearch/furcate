if(IDF_TARGET STREQUAL "esp32p4")
    idf_component_register(SRCS "fl_models_none.c"
                           INCLUDE_DIRS "include"
                           REQUIRES fl_core)
else()
    idf_component_register(SRCS "fl_models.cc"
                           INCLUDE_DIRS "include"
                           REQUIRES fl_core esp_partition esp_timer esp_rom)
endif()
