/*  This file is part of the KDE libraries
    SPDX-FileCopyrightText: 2000 Malte Starostik <malte@kde.org>

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#ifndef _TEXTCREATOR_H_
#define _TEXTCREATOR_H_

#include <QPixmap>
#include <kio/thumbcreator.h>
#include <KSyntaxHighlighting/Repository>

class TextCreator : public ThumbCreator
{
public:
    TextCreator();
    ~TextCreator() override;
    bool create(const QString &path, int width, int height, QImage &img) override;

private:
    char *m_data;
    int m_dataSize;
    QPixmap m_pixmap;

    KSyntaxHighlighting::Repository m_highlightingRepository;
};

#endif
