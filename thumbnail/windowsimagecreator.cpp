/*
    windowsimagecreator.cpp - Thumbnail Creator for Microsoft Windows Images

    Copyright (c) 2009 by Pali Rohár <pali.rohar@gmail.com>

    *************************************************************************
    *                                                                       *
    * This library is free software; you can redistribute it and/or         *
    * modify it under the terms of the GNU General Public                   *
    * License as published by the Free Software Foundation; either          *
    * version 2 of the License, or (at your option) any later version.      *
    *                                                                       *
    *************************************************************************
*/

#include "windowsimagecreator.h"
#include "icoutils.h"

#include <QString>
#include <QImage>
#include <QImageReader>
#include <QMimeDatabase>

extern "C"
{
    Q_DECL_EXPORT ThumbCreator *new_creator()
    {
        return new WindowsImageCreator;
    }
}

bool WindowsImageCreator::create(const QString &path, int width, int height, QImage &img)
{
    if (IcoUtils::loadIcoImage(path, img, width, height)) {
        return true;
    }

    // Maybe it's an animated cursor
    if (QMimeDatabase().mimeTypeForFile(path).name() == QLatin1String("application/x-navi-animation")) {
        QImageReader reader(path, "ani");
        return reader.read(&img);
    }

    return false;

}
