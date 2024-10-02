add_definitions(-DTRANSLATION_DOMAIN=\"kio6_9p\")

remove_definitions(-DQT_NO_CAST_FROM_ASCII)

add_library(kio_9p MODULE)
set_target_properties(kio_9p PROPERTIES
    OUTPUT_NAME "9p"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/kf6/kio"
)

target_sources(kio_9p PRIVATE kio_9p.cpp)

ecm_qt_declare_logging_category(kio_9p
    HEADER kio_9p_debug.h
    IDENTIFIER KIO_9P_LOG
    CATEGORY_NAME kf.kio.workers.9p
    OLD_CATEGORY_NAMES log_kio_9p kf.kio.slaves.9p
    DESCRIPTION "KIO 9p"
    EXPORT KIO_EXTRAS
)

ecm_qt_declare_logging_category(kio_9p
    HEADER kio_9p_trace_debug.h
    IDENTIFIER KIO_9P_TRACE_LOG
    CATEGORY_NAME kf.kio.workers.9p.trace
    OLD_CATEGORY_NAMES log_kio_9p.trace kf.kio.slaves.9p.trace
    DESCRIPTION "KIO 9p (trace)"
    EXPORT KIO_EXTRAS
)

if(WIN32)
    target_include_directories(kio_9p PRIVATE ${QT_MKSPECS_DIR}/default) # for SYMLINKS
endif()

target_link_libraries(kio_9p
    PRIVATE
        KF6::KIOCore
        KF6::ConfigCore
        KF6::I18n
        Qt::Network
        QCoro::Core
        ssh
)
kde_target_enable_exceptions(kio_9p PRIVATE)

install(TARGETS kio_9p DESTINATION ${KDE_INSTALL_PLUGINDIR}/kf6/kio)
