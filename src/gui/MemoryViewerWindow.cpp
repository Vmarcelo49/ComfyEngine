#include "gui/MemoryViewerWindow.h"

#include "core/CodeInjector.h"
#include "core/TargetProcess.h"
#include "gui/MainWindow.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QHeaderView>
#include <QLabel>
#include <QInputDialog>
#include <QSpinBox>
#include <QCheckBox>
#include <QSplitter>
#include <QTimer>
#include <QMenu>
#include <QClipboard>
#include <QGuiApplication>
#include <QRegularExpression>
#include <QMessageBox>
#include <QFontDatabase>
#include <QMenuBar>
#include <QToolBar>
#include <QToolButton>
#include <QStyle>
#include <QApplication>
#include <QDockWidget>
#include <QAction>
#include <QSize>
#include <QColor>
#include <QShowEvent>
#include <QTreeWidget>
#include <QTreeWidgetItem>

#include <capstone/capstone.h>

#include <vector>

namespace {
QColor instructionColor(const QString &mnemonic) {
    const QString lower = mnemonic.toLower();
    if (lower.startsWith("add") || lower.startsWith("inc")) return QColor("#6cc644");
    if (lower.startsWith("sub") || lower.startsWith("dec") || lower.startsWith("cmp")) return QColor("#f45b69");
    if (lower.startsWith("jmp") || lower.startsWith("call")) return QColor("#56b6c2");
    if (lower.startsWith("mov")) return QColor("#ffd166");
    return QColor(Qt::white);
}
}

MemoryViewerWindow::MemoryViewerWindow(QWidget *parent)
    : QMainWindow(parent) {
    setupUi();
}

void MemoryViewerWindow::setupUi() {
    auto *toolsMenu = menuBar()->addMenu("Tools");
    QAction *autoAsmAct = toolsMenu->addAction("Auto Assembler...");
    QAction *aobAct = toolsMenu->addAction("AoB Injection...");
    QAction *ptrScanAct = toolsMenu->addAction("Pointer Scanner...");
    connect(autoAsmAct, &QAction::triggered, this, &MemoryViewerWindow::triggerAutoAssembler);
    connect(aobAct, &QAction::triggered, this, &MemoryViewerWindow::triggerAobInjection);
    connect(ptrScanAct, &QAction::triggered, this, &MemoryViewerWindow::triggerPointerScanner);

    auto *central = new QWidget(this);
    auto *layout = new QVBoxLayout(central);

    auto *navBar = addToolBar("Navigation");
    navBar->setMovable(false);
    navBar->setFloatable(false);
    navBar->setIconSize(QSize(18, 18));
    navBar->addWidget(new QLabel("Address", this));
    addrEdit_ = new QLineEdit(this);
    addrEdit_->setFixedWidth(160);
    navBar->addWidget(addrEdit_);
    auto *style = QApplication::style();
    auto goAction = navBar->addAction(style ? style->standardIcon(QStyle::SP_ArrowForward) : QIcon(), "Go");
    auto prevAction = navBar->addAction(style ? style->standardIcon(QStyle::SP_ArrowBack) : QIcon(), "Prev page");
    auto nextAction = navBar->addAction(style ? style->standardIcon(QStyle::SP_ArrowForward) : QIcon(), "Next page");
    auto refreshAction = navBar->addAction(style ? style->standardIcon(QStyle::SP_BrowserReload) : QIcon(), "Refresh");
    navBar->addSeparator();
    regionLabel_ = new QLabel("No process", this);
    regionLabel_->setStyleSheet("color:#7fdcff;");
    navBar->addWidget(regionLabel_);
    auto *optionsButton = new QToolButton(this);
    optionsButton->setText("Options");
    optionsButton->setCheckable(true);
    navBar->addWidget(optionsButton);

    autoRefreshCheck_ = new QCheckBox("Auto refresh", this);
    autoRefreshCheck_->setChecked(false);
    refreshIntervalSpin_ = new QSpinBox(this);
    refreshIntervalSpin_->setRange(50, 5000);
    refreshIntervalSpin_->setSingleStep(50);
    refreshIntervalSpin_->setValue(250);
    refreshIntervalSpin_->setSuffix(" ms");
    bytesPerPageSpin_ = new QSpinBox(this);
    bytesPerPageSpin_->setRange(256, 65536);
    bytesPerPageSpin_->setSingleStep(256);
    bytesPerPageSpin_->setValue(static_cast<int>(rows_ * bytesPerRow_));
    execOnlyCheck_ = new QCheckBox("Exec only", this);

    auto *optionsPanel = new QWidget(this);
    auto *optionsLayout = new QGridLayout(optionsPanel);
    optionsLayout->setContentsMargins(6, 6, 6, 6);
    optionsLayout->setHorizontalSpacing(10);
    optionsLayout->setVerticalSpacing(4);
    optionsLayout->addWidget(autoRefreshCheck_, 0, 0);
    optionsLayout->addWidget(refreshIntervalSpin_, 0, 1);
    optionsLayout->addWidget(new QLabel("Bytes/page", this), 1, 0);
    optionsLayout->addWidget(bytesPerPageSpin_, 1, 1);
    optionsLayout->addWidget(execOnlyCheck_, 2, 0, 1, 2);
    optionsPanel->setVisible(false);
    layout->addWidget(optionsPanel);
    connect(optionsButton, &QToolButton::toggled, optionsPanel, &QWidget::setVisible);
    connect(goAction, &QAction::triggered, this, &MemoryViewerWindow::onGo);
    connect(prevAction, &QAction::triggered, this, &MemoryViewerWindow::onPrevPage);
    connect(nextAction, &QAction::triggered, this, &MemoryViewerWindow::onNextPage);
    connect(refreshAction, &QAction::triggered, this, [this]() {
        refreshRegions();
        refreshView();
    });

    regionTable_ = new QTableWidget(this);
    regionTable_->setColumnCount(5);
    regionTable_->setHorizontalHeaderLabels({"Start", "End", "Perms", "Size", "File"});
    regionTable_->horizontalHeader()->setStretchLastSection(true);
    regionTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    regionTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    regionTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    regionTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    regionTable_->verticalHeader()->setVisible(false);
    regionTable_->setAlternatingRowColors(true);
    regionTable_->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    regionTable_->setShowGrid(false);
    regionTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    regionTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    regionTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    regionTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);

    regionDock_ = new QDockWidget("Memory Regions", this);
    regionDock_->setWidget(regionTable_);
    addDockWidget(Qt::LeftDockWidgetArea, regionDock_);
    regionDock_->hide();
    auto viewMenu = menuBar()->addMenu("View");
    viewMenu->addAction(regionDock_->toggleViewAction());

    auto *cheatWidget = new QWidget(this);
    auto *cheatLayout = new QVBoxLayout(cheatWidget);
    cheatLayout->setContentsMargins(6, 6, 6, 6);
    cheatLayout->setSpacing(6);
    cheatList_ = new QTreeWidget(this);
    cheatList_->setColumnCount(2);
    cheatList_->setHeaderLabels({"Description", "Address"});
    cheatList_->setRootIsDecorated(false);
    cheatList_->setAlternatingRowColors(true);
    cheatList_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    cheatList_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    cheatList_->setContextMenuPolicy(Qt::CustomContextMenu);
    cheatLayout->addWidget(cheatList_);
    auto *cheatControls = new QHBoxLayout;
    cheatDescEdit_ = new QLineEdit(this);
    cheatDescEdit_->setPlaceholderText("Label (optional)");
    auto *cheatAddBtn = new QPushButton("Add selection", this);
    auto *cheatRemoveBtn = new QPushButton("Remove", this);
    cheatControls->addWidget(cheatDescEdit_);
    cheatControls->addWidget(cheatAddBtn);
    cheatControls->addWidget(cheatRemoveBtn);
    cheatLayout->addLayout(cheatControls);
    cheatDock_ = new QDockWidget("Cheat List", this);
    cheatDock_->setWidget(cheatWidget);
    addDockWidget(Qt::LeftDockWidgetArea, cheatDock_);
    tabifyDockWidget(regionDock_, cheatDock_);
    cheatDock_->hide();
    viewMenu->addAction(cheatDock_->toggleViewAction());

    auto *splitter = new QSplitter(Qt::Vertical, this);

    // Disassembler-like top table (simple bytes/opcode view)
    disasmTable_ = new QTableWidget(this);
    disasmTable_->setColumnCount(3);
    disasmTable_->setHorizontalHeaderLabels({"Address", "Bytes", "Opcode"});
    disasmTable_->setRowCount(static_cast<int>(rows_));
    disasmTable_->verticalHeader()->setVisible(false);
    disasmTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    disasmTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    disasmTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    disasmTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    disasmTable_->setAlternatingRowColors(true);
    disasmTable_->setShowGrid(false);
    disasmTable_->setWordWrap(false);
    disasmTable_->horizontalHeader()->setStretchLastSection(true);
    disasmTable_->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    disasmTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    disasmTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    disasmTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    splitter->addWidget(disasmTable_);
    connect(disasmTable_, &QTableWidget::itemSelectionChanged, this, [this]() {
        if (!disasmTable_) return;
        auto *item = disasmTable_->currentItem();
        if (!item) return;
        int row = item->row();
        auto *addrItem = disasmTable_->item(row, 0);
        if (!addrItem) return;
        bool ok = false;
        uintptr_t addr = addrItem->text().toULongLong(&ok, 0);
        if (ok) updateSelectionAddress(addr);
    });

    hexTable_ = new QTableWidget(this);
    hexTable_->setColumnCount(static_cast<int>(bytesPerRow_) + 2);
    QStringList headers;
    headers << "Address";
    for (size_t i = 0; i < bytesPerRow_; ++i) {
        headers << QString::asprintf("%02X", static_cast<unsigned int>(i));
    }
    headers << "ASCII";
    hexTable_->setHorizontalHeaderLabels(headers);
    hexTable_->setRowCount(static_cast<int>(rows_));
    hexTable_->verticalHeader()->setVisible(false);
    hexTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    hexTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    hexTable_->setSelectionBehavior(QAbstractItemView::SelectItems);
    hexTable_->horizontalHeader()->setStretchLastSection(true);
    hexTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    hexTable_->setAlternatingRowColors(true);
    hexTable_->setShowGrid(false);
    hexTable_->setWordWrap(false);
    hexTable_->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    hexTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    hexTable_->horizontalHeader()->setDefaultSectionSize(36);
    hexTable_->verticalHeader()->setDefaultSectionSize(20);
    int asciiColumn = static_cast<int>(bytesPerRow_) + 1;
    hexTable_->horizontalHeader()->setSectionResizeMode(asciiColumn, QHeaderView::Stretch);
    splitter->addWidget(hexTable_);
    connect(hexTable_, &QTableWidget::itemSelectionChanged, this, [this]() {
        if (!hexTable_) return;
        auto items = hexTable_->selectedItems();
        if (items.isEmpty()) return;
        int row = items.first()->row();
        int col = items.first()->column();
        if (col <= 0 || col > static_cast<int>(bytesPerRow_)) return;
        auto *addrItem = hexTable_->item(row, 0);
        if (!addrItem) return;
        bool ok = false;
        uintptr_t base = addrItem->text().toULongLong(&ok, 0);
        if (!ok) return;
        uintptr_t addr = base + static_cast<uintptr_t>(col - 1);
        updateSelectionAddress(addr);
    });
    splitter->setStretchFactor(0, 2);
    splitter->setStretchFactor(1, 3);
    layout->addWidget(splitter);

    setCentralWidget(central);
    setWindowTitle("Memory Viewer");
    resize(900, 600);

    refreshTimer_ = new QTimer(this);
    refreshTimer_->setInterval(refreshIntervalSpin_->value());
    connect(refreshTimer_, &QTimer::timeout, this, [this]() {
        refreshView();
    });

    connect(bytesPerPageSpin_, qOverload<int>(&QSpinBox::valueChanged), this, [this](int v) {
        size_t total = static_cast<size_t>(v);
        rows_ = total / bytesPerRow_;
        disasmTable_->setRowCount(static_cast<int>(rows_));
        hexTable_->setRowCount(static_cast<int>(rows_));
        refreshView();
    });
    connect(hexTable_, &QTableWidget::cellDoubleClicked, this, &MemoryViewerWindow::onCellDoubleClicked);
    connect(regionTable_, &QTableWidget::cellDoubleClicked, this, &MemoryViewerWindow::onRegionDoubleClicked);
    connect(regionTable_, &QTableWidget::customContextMenuRequested, this, &MemoryViewerWindow::onRegionContextMenu);
    connect(execOnlyCheck_, &QCheckBox::checkStateChanged, this, [this](Qt::CheckState) {
        refreshView();
    });
    connect(disasmTable_, &QTableWidget::customContextMenuRequested, this, &MemoryViewerWindow::onDisasmContextMenu);
    connect(hexTable_, &QTableWidget::customContextMenuRequested, this, &MemoryViewerWindow::onHexContextMenu);
    connect(autoRefreshCheck_, &QCheckBox::toggled, this, [this](bool enabled) {
        setAutoRefresh(enabled);
    });
    connect(refreshIntervalSpin_, qOverload<int>(&QSpinBox::valueChanged), this, [this](int v) {
        refreshTimer_->setInterval(v);
        if (autoRefreshCheck_->isChecked()) {
            refreshTimer_->start(v);
        }
    });
    setAutoRefresh(false);
    applyStyle();

    connect(cheatAddBtn, &QPushButton::clicked, this, [this]() {
        uintptr_t addr = currentSelectionAddress();
        if (addr == 0) {
            QMessageBox::information(this, "Cheat List", "Select an address first (click a row in the view).");
            return;
        }
        QString desc = cheatDescEdit_ ? cheatDescEdit_->text().trimmed() : QString();
        if (desc.isEmpty()) {
            desc = QStringLiteral("Entry %1").arg(cheatList_ ? cheatList_->topLevelItemCount() + 1 : 1);
        }
        if (!cheatList_) return;
        auto *item = new QTreeWidgetItem(cheatList_);
        item->setText(0, desc);
        item->setText(1, QString::asprintf("0x%llx", static_cast<unsigned long long>(addr)));
        cheatList_->scrollToItem(item);
        if (cheatDescEdit_) cheatDescEdit_->clear();
        if (cheatDock_ && !cheatDock_->isVisible()) cheatDock_->show();
    });
    connect(cheatRemoveBtn, &QPushButton::clicked, this, [this]() {
        if (!cheatList_) return;
        auto items = cheatList_->selectedItems();
        for (auto *it : items) {
            delete it;
        }
    });
    connect(cheatList_, &QTreeWidget::itemActivated, this, [this](QTreeWidgetItem *item, int) {
        if (!item) return;
        bool ok = false;
        uintptr_t addr = item->text(1).toULongLong(&ok, 0);
        if (ok) jumpTo(addr);
    });
    connect(cheatList_, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
        if (!cheatList_) return;
        auto *item = cheatList_->itemAt(pos);
        QMenu menu(this);
        QAction *copyAddr = menu.addAction("Copy address");
        QAction *jumpAct = menu.addAction("Jump to address");
        QAction *chosen = menu.exec(cheatList_->viewport()->mapToGlobal(pos));
        if (!chosen || !item) return;
        bool ok = false;
        uintptr_t addr = item->text(1).toULongLong(&ok, 0);
        if (!ok) return;
        if (chosen == copyAddr) {
            copyToClipboard(item->text(1));
        } else if (chosen == jumpAct) {
            jumpTo(addr);
        }
    });
}

void MemoryViewerWindow::setTarget(core::TargetProcess *proc, uintptr_t address, core::CodeInjector *injector) {
    proc_ = proc;
    injector_ = injector;
    patchBackups_.clear();
    if (!proc_ || address == 0) {
        lastSelectedAddress_ = 0;
        regionLabel_->setText("No process");
        regionTable_->setRowCount(0);
        setAutoRefresh(false);
        return;
    }
    if (!isVisible()) {
        deferredAddress_ = address;
        deferredRefresh_ = true;
        regionLabel_->setText("Ready");
        return;
    }
    refreshRegions();
    jumpTo(address);
    setAutoRefresh(autoRefreshCheck_->isChecked());
    updateSelectionAddress(address);
}

void MemoryViewerWindow::jumpTo(uintptr_t address) {
    if (!proc_ || address == 0) return;
    baseAddress_ = address - (address % bytesPerRow_);
    addrEdit_->setText(QString::asprintf("0x%llx", static_cast<unsigned long long>(baseAddress_)));
    selectRegionFor(baseAddress_);
    refreshView();
    updateSelectionAddress(address);
}

void MemoryViewerWindow::onGo() {
    if (!proc_) {
        lastReadFailed_ = false;
        return;
    }
    bool ok = false;
    uintptr_t addr = addrEdit_->text().toULongLong(&ok, 0);
    if (!ok || addr == 0) return;
    jumpTo(addr);
}

void MemoryViewerWindow::onPrevPage() {
    if (!proc_ || baseAddress_ < rows_ * bytesPerRow_) return;
    baseAddress_ -= rows_ * bytesPerRow_;
    addrEdit_->setText(QString::asprintf("0x%llx", static_cast<unsigned long long>(baseAddress_)));
    selectRegionFor(baseAddress_);
    refreshView();
}

void MemoryViewerWindow::onNextPage() {
    if (!proc_) return;
    baseAddress_ += rows_ * bytesPerRow_;
    addrEdit_->setText(QString::asprintf("0x%llx", static_cast<unsigned long long>(baseAddress_)));
    selectRegionFor(baseAddress_);
    refreshView();
}

void MemoryViewerWindow::refreshView() {
    if (!proc_) return;
    const auto regions = proc_->regions();
    // Optionally snap baseAddress_ to first executable region containing it
    uintptr_t effectiveBase = baseAddress_;
    if (execOnlyCheck_ && execOnlyCheck_->isChecked()) {
        bool found = false;
        for (const auto &reg : regions) {
            if (reg.perms.find('x') == std::string::npos) continue;
            if (effectiveBase >= reg.start && effectiveBase < reg.end) {
                effectiveBase = reg.start;
                found = true;
                break;
            }
        }
        if (!found) {
            // Fallback: first executable region
            for (const auto &reg : regions) {
                if (reg.perms.find('x') == std::string::npos) continue;
                effectiveBase = reg.start;
                found = true;
                break;
            }
        }
        if (!found) {
            regionLabel_->setText("No executable region");
            if (!lastReadFailed_) {
                lastReadFailed_ = true;
                QMessageBox::warning(this, "Memory Viewer", "No executable region matches the requested address.");
            }
            return;
        }
    }
    const size_t totalBytes = rows_ * bytesPerRow_;
    std::vector<uint8_t> buf(totalBytes);
    if (!proc_->readMemory(effectiveBase, buf.data(), totalBytes)) {
        regionLabel_->setText("Read failed");
        if (!lastReadFailed_) {
            lastReadFailed_ = true;
            QMessageBox::warning(this, "Memory Viewer",
                                 QString("Failed to read process memory at 0x%1.")
                                     .arg(QString::asprintf("%llx", static_cast<unsigned long long>(effectiveBase))));
        }
        return;
    }
    lastReadFailed_ = false;

    // region info (best effort)
    QString regionInfo = "Unknown region";
    for (const auto &reg : regions) {
        if (effectiveBase >= reg.start && effectiveBase < reg.end) {
            regionInfo = QString("Region %1-%2 %3 %4")
                .arg(QString::asprintf("0x%llx", static_cast<unsigned long long>(reg.start)))
                .arg(QString::asprintf("0x%llx", static_cast<unsigned long long>(reg.end)))
                .arg(QString::fromStdString(reg.perms))
                .arg(QString::fromStdString(reg.path));
            break;
        }
    }
    regionLabel_->setText(regionInfo);

    // Clear old contents
    disasmTable_->clearContents();

    // Disassemble buffer using Capstone (x86-64). If this fails or yields no
    // instructions, fall back to a simple db/hex listing so the user still
    // sees something meaningful.
    csh handle;
    bool disasmOk = (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK);
    size_t count = 0;
    cs_insn *insn = nullptr;
    if (disasmOk) {
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        count = cs_disasm(handle, buf.data(), totalBytes,
                          effectiveBase, 0, &insn);
    }

    if (disasmOk && count > 0) {
        size_t maxRows = rows_;
        size_t rowCount = count < maxRows ? count : maxRows;
        disasmTable_->setRowCount(static_cast<int>(rowCount));
        for (size_t i = 0; i < rowCount; ++i) {
            const cs_insn &ci = insn[i];
            auto *addrItem = new QTableWidgetItem(
                QString::asprintf("0x%016llx",
                    static_cast<unsigned long long>(ci.address)));
            QString bytesStr;
            for (size_t b = 0; b < ci.size; ++b) {
                bytesStr += QString::asprintf("%02x ", ci.bytes[b]);
            }
            bytesStr = bytesStr.trimmed();
            auto *bytesItem = new QTableWidgetItem(bytesStr);
            QString opcodeStr = QString("%1 %2")
                .arg(ci.mnemonic)
                .arg(ci.op_str);
            auto *opItem = new QTableWidgetItem(opcodeStr.trimmed());
            opItem->setForeground(instructionColor(QString::fromLatin1(ci.mnemonic)));
            int row = static_cast<int>(i);
            disasmTable_->setItem(row, 0, addrItem);
            disasmTable_->setItem(row, 1, bytesItem);
            disasmTable_->setItem(row, 2, opItem);
        }
    } else {
        // Fallback: show raw bytes as db listings, one row per 16 bytes.
        disasmTable_->setRowCount(static_cast<int>(rows_));
        for (int row = 0; row < static_cast<int>(rows_); ++row) {
            uintptr_t rowAddr = effectiveBase + static_cast<uintptr_t>(row) * bytesPerRow_;
            auto *addrItem = new QTableWidgetItem(QString::asprintf("0x%016llx",
                static_cast<unsigned long long>(rowAddr)));
            size_t baseIndex = static_cast<size_t>(row) * bytesPerRow_;
            QString bytesStr;
            for (size_t i = 0; i < bytesPerRow_ && baseIndex + i < buf.size(); ++i) {
                bytesStr += QString::asprintf("%02x ", buf[baseIndex + i]);
            }
            bytesStr = bytesStr.trimmed();
            auto *bytesItem = new QTableWidgetItem(bytesStr);
            auto *opItem = new QTableWidgetItem(QString("db %1").arg(bytesStr));
            opItem->setForeground(QBrush(Qt::gray));
            disasmTable_->setItem(row, 0, addrItem);
            disasmTable_->setItem(row, 1, bytesItem);
            disasmTable_->setItem(row, 2, opItem);
        }
    }

    if (disasmOk) {
        cs_free(insn, count);
        cs_close(&handle);
    }

    for (int row = 0; row < static_cast<int>(rows_); ++row) {
        uintptr_t rowAddr = effectiveBase + static_cast<uintptr_t>(row) * bytesPerRow_;
        // Hex row
        auto *addrItem = new QTableWidgetItem(QString::asprintf("0x%016llx",
            static_cast<unsigned long long>(rowAddr)));
        hexTable_->setItem(row, 0, addrItem);
        QString ascii;
        for (int col = 0; col < static_cast<int>(bytesPerRow_); ++col) {
            size_t index = static_cast<size_t>(row) * bytesPerRow_ + static_cast<size_t>(col);
            QString cellText;
            if (index < buf.size()) {
                uint8_t b = buf[index];
                cellText = QString::asprintf("%02x", b);
                ascii += (b >= 32 && b <= 126) ? QChar(b) : '.';
            } else {
                cellText = "";
                ascii += ' ';
            }
            auto *byteItem = new QTableWidgetItem(cellText);
            hexTable_->setItem(row, col + 1, byteItem);
        }
        auto *asciiItem = new QTableWidgetItem(ascii);
        hexTable_->setItem(row, static_cast<int>(bytesPerRow_) + 1, asciiItem);
    }
}

void MemoryViewerWindow::refreshRegions() {
    if (!proc_ || !proc_->isAttached()) {
        regionTable_->setRowCount(0);
        regionLabel_->setText("No process");
        setAutoRefresh(false);
        return;
    }
    auto regs = proc_->regions();
    regionTable_->setRowCount(static_cast<int>(regs.size()));
    for (int i = 0; i < static_cast<int>(regs.size()); ++i) {
        const auto &r = regs[static_cast<size_t>(i)];
        auto *startItem = new QTableWidgetItem(QString::asprintf("0x%llx",
            static_cast<unsigned long long>(r.start)));
        auto *endItem = new QTableWidgetItem(QString::asprintf("0x%llx",
            static_cast<unsigned long long>(r.end)));
        auto *permItem = new QTableWidgetItem(QString::fromStdString(r.perms));
        auto *sizeItem = new QTableWidgetItem(QString::number(
            static_cast<qulonglong>(r.end - r.start)));
        auto *fileItem = new QTableWidgetItem(QString::fromStdString(r.path));
        regionTable_->setItem(i, 0, startItem);
        regionTable_->setItem(i, 1, endItem);
        regionTable_->setItem(i, 2, permItem);
        regionTable_->setItem(i, 3, sizeItem);
        regionTable_->setItem(i, 4, fileItem);
    }
}

void MemoryViewerWindow::selectRegionFor(uintptr_t address) {
    for (int i = 0; i < regionTable_->rowCount(); ++i) {
        auto *startItem = regionTable_->item(i, 0);
        auto *endItem = regionTable_->item(i, 1);
        if (!startItem || !endItem) continue;
        bool ok1 = false, ok2 = false;
        uintptr_t start = startItem->text().toULongLong(&ok1, 0);
        uintptr_t end = endItem->text().toULongLong(&ok2, 0);
        if (ok1 && ok2 && address >= start && address < end) {
            regionTable_->setCurrentCell(i, 0);
            regionTable_->scrollToItem(startItem, QAbstractItemView::PositionAtCenter);
            return;
        }
    }
}

void MemoryViewerWindow::onCellDoubleClicked(int row, int column) {
    if (!proc_ || column == 0 || column == static_cast<int>(bytesPerRow_) + 1) return;
    bool okAddr = false;
    auto *addrItem = hexTable_->item(row, 0);
    if (!addrItem) return;
    uintptr_t rowAddr = addrItem->text().toULongLong(&okAddr, 0);
    if (!okAddr) return;
    uintptr_t addr = rowAddr + static_cast<uintptr_t>(column - 1);
    updateSelectionAddress(addr);

    auto *cell = hexTable_->item(row, column);
    QString current = cell ? cell->text() : "";
    bool okVal = false;
    QString text = QInputDialog::getText(this, "Edit byte", "New value (hex):",
                                         QLineEdit::Normal, current, &okVal);
    if (!okVal || text.isEmpty()) return;
    bool okHex = false;
    uint8_t value = static_cast<uint8_t>(text.toUShort(&okHex, 16));
    if (!okHex) return;
    uint8_t buf = value;
    if (!proc_->writeMemory(addr, &buf, sizeof(buf))) return;
    refreshView();
}

void MemoryViewerWindow::onRegionDoubleClicked(int row, int /*column*/) {
    if (row < 0) return;
    auto *startItem = regionTable_->item(row, 0);
    if (!startItem) return;
    bool ok = false;
    uintptr_t addr = startItem->text().toULongLong(&ok, 0);
    if (!ok) return;
    jumpTo(addr);
}

void MemoryViewerWindow::copyToClipboard(const QString &text) {
    if (text.isEmpty()) return;
    if (auto *clip = QGuiApplication::clipboard()) {
        clip->setText(text);
    }
}

bool MemoryViewerWindow::ensurePatchBackup(uintptr_t address, size_t length) {
    if (!proc_ || address == 0 || length == 0) return false;
    if (patchBackups_.find(address) != patchBackups_.end()) return true;
    std::vector<uint8_t> original(length);
    if (!proc_->readMemory(address, original.data(), original.size())) {
        return false;
    }
    patchBackups_[address] = std::move(original);
    return true;
}

void MemoryViewerWindow::restorePatchedBytes(uintptr_t address) {
    if (!proc_) return;
    if (injector_) {
        if (!injector_->restore(address)) {
            QMessageBox::warning(this, "Undo patch", "No patch found or failed to restore bytes.");
            return;
        }
        refreshView();
        return;
    }
    auto it = patchBackups_.find(address);
    if (it == patchBackups_.end()) return;
    if (!proc_->writeMemory(address, it->second.data(), it->second.size())) {
        QMessageBox::warning(this, "Undo patch", "Failed to restore bytes.");
        return;
    }
    patchBackups_.erase(it);
    refreshView();
}

uintptr_t MemoryViewerWindow::currentSelectionAddress() const {
    return lastSelectedAddress_ ? lastSelectedAddress_ : baseAddress_;
}

void MemoryViewerWindow::updateSelectionAddress(uintptr_t address) {
    if (address == 0) return;
    lastSelectedAddress_ = address;
    if (auto *main = MainWindow::instance()) {
        main->updateGlobalAddress(address, core::ValueType::Int64, QStringLiteral("Memory viewer"));
    }
}

std::vector<uint8_t> MemoryViewerWindow::readBytes(uintptr_t address, size_t length) const {
    std::vector<uint8_t> out;
    if (!proc_ || address == 0 || length == 0) return out;
    out.resize(length);
    if (!proc_->readMemory(address, out.data(), out.size())) {
        out.clear();
    }
    return out;
}

void MemoryViewerWindow::triggerAutoAssembler() {
    if (auto *main = MainWindow::instance()) {
        uintptr_t addr = currentSelectionAddress();
        auto bytes = readBytes(addr, 10);
        main->openAutoAssemblerAt(addr, bytes);
    }
}

void MemoryViewerWindow::triggerAobInjection() {
    if (auto *main = MainWindow::instance()) {
        main->openAobInjectionAt(currentSelectionAddress());
    }
}

void MemoryViewerWindow::triggerPointerScanner() {
    if (auto *main = MainWindow::instance()) {
        main->openPointerScannerAt(currentSelectionAddress());
    }
}

void MemoryViewerWindow::showEvent(QShowEvent *event) {
    QMainWindow::showEvent(event);
    if (deferredRefresh_ && proc_ && deferredAddress_ != 0) {
        refreshRegions();
        jumpTo(deferredAddress_);
        setAutoRefresh(autoRefreshCheck_->isChecked());
        updateSelectionAddress(deferredAddress_);
        deferredRefresh_ = false;
        deferredAddress_ = 0;
    }
}

void MemoryViewerWindow::applyStyle() {
    QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    mono.setPointSize(std::max(10, font().pointSize()));
    if (hexTable_) hexTable_->setFont(mono);
    if (disasmTable_) disasmTable_->setFont(mono);
    if (regionTable_) regionTable_->setFont(mono);

    QString style = R"(
        QTableWidget {
            background-color: #111111;
            border: 1px solid #2b2b2b;
            gridline-color: #2b2b2b;
        }
        QTableWidget::item:selected {
            background-color: #2f6fed;
            color: #ffffff;
        }
        QLineEdit {
            background-color: #151515;
            border: 1px solid #383838;
            border-radius: 4px;
            padding: 2px 6px;
        }
    )";
    setStyleSheet(style);
}

void MemoryViewerWindow::patchBytes(uintptr_t address, const QString &defaultBytes) {
    if (!proc_ || address == 0) return;
    updateSelectionAddress(address);
    bool ok = false;
    QString prompt = QString("Write bytes at 0x%1 (hex, spaced)").arg(QString::asprintf("%llx", static_cast<unsigned long long>(address)));
    QString text = QInputDialog::getText(this, "Patch bytes", prompt, QLineEdit::Normal, defaultBytes, &ok);
    if (!ok) return;
    QString trimmed = text.trimmed();
    if (trimmed.isEmpty()) return;
    QStringList parts = trimmed.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
    std::vector<uint8_t> bytes;
    bytes.reserve(parts.size());
    for (const QString &part : parts) {
        bool byteOk = false;
        uint8_t val = static_cast<uint8_t>(part.toUInt(&byteOk, 16));
        if (!byteOk) {
            QMessageBox::warning(this, "Patch bytes", QString("Invalid byte: %1").arg(part));
            return;
        }
        bytes.push_back(val);
    }
    if (bytes.empty()) return;
    if (injector_) {
        if (!injector_->patchBytes(address, bytes)) {
            QMessageBox::warning(this, "Patch bytes", "Failed to write memory.");
            return;
        }
        refreshView();
        return;
    }
    if (!ensurePatchBackup(address, bytes.size())) {
        QMessageBox::warning(this, "Patch bytes", "Could not read original bytes for undo.");
    }
    if (!proc_->writeMemory(address, bytes.data(), bytes.size())) {
        QMessageBox::warning(this, "Patch bytes", "Failed to write memory.");
        return;
    }
    refreshView();
}

void MemoryViewerWindow::onHexContextMenu(const QPoint &pos) {
    if (!proc_) return;
    auto *item = hexTable_->itemAt(pos);
    if (!item) return;
    int row = item->row();
    int col = item->column();
    auto *addrItem = hexTable_->item(row, 0);
    if (!addrItem) return;
    bool ok = false;
    uintptr_t rowAddr = addrItem->text().toULongLong(&ok, 0);
    if (!ok) return;
    uintptr_t cellAddr = (col > 0 && col <= static_cast<int>(bytesPerRow_))
        ? rowAddr + static_cast<uintptr_t>(col - 1)
        : rowAddr;

    updateSelectionAddress(cellAddr);

    QMenu menu(this);
    QAction *copyAddr = menu.addAction("Copy address");
    QAction *copyValue = nullptr;
    QAction *editValue = nullptr;
    QAction *jumpDisasm = nullptr;
    QAction *restoreAction = nullptr;

    if (col == 0) {
        // only address copy
    } else if (col == static_cast<int>(bytesPerRow_) + 1) {
        copyValue = menu.addAction("Copy ASCII");
    } else {
        copyValue = menu.addAction("Copy byte value");
        editValue = menu.addAction("Edit byte...");
        jumpDisasm = menu.addAction("Jump to instruction");
        bool hasPatch = injector_ ? injector_->patches().count(cellAddr) > 0
                                  : patchBackups_.find(cellAddr) != patchBackups_.end();
        if (hasPatch) {
            restoreAction = menu.addAction("Restore original instruction");
        }
    }

    QAction *chosen = menu.exec(hexTable_->viewport()->mapToGlobal(pos));
    if (!chosen) return;
    // Re-fetch current items in case the view refreshed while menu was open.
    auto *addrNow = hexTable_->item(row, 0);
    auto *cellNow = hexTable_->item(row, col);

    if (chosen == copyAddr) {
        copyToClipboard(QString::asprintf("0x%016llx", static_cast<unsigned long long>(cellAddr)));
    } else if (chosen == copyValue && cellNow) {
        copyToClipboard(cellNow->text());
    } else if (chosen == editValue && cellNow) {
        patchBytes(cellAddr, cellNow->text());
    } else if (chosen == jumpDisasm) {
        baseAddress_ = cellAddr;
        refreshView();
    } else if (chosen == restoreAction) {
        restorePatchedBytes(cellAddr);
    }
}

void MemoryViewerWindow::onDisasmContextMenu(const QPoint &pos) {
    if (!proc_) return;
    auto *item = disasmTable_->itemAt(pos);
    if (!item) return;
    int row = item->row();
    auto *addrItem = disasmTable_->item(row, 0);
    if (!addrItem) return;
    auto *bytesItem = disasmTable_->item(row, 1);
    auto *opItem = disasmTable_->item(row, 2);
    bool ok = false;
    uintptr_t addr = addrItem->text().toULongLong(&ok, 0);
    if (!ok) return;

    updateSelectionAddress(addr);

    QMenu menu(this);
    QAction *copyAddr = menu.addAction("Copy address");
    QAction *copyBytes = menu.addAction("Copy bytes");
    QAction *copyInstr = menu.addAction("Copy instruction");
    QAction *nopOut = menu.addAction("Replace with NOPs");
    QAction *patch = menu.addAction("Patch bytes...");
    QAction *restoreAction = nullptr;
    bool hasPatch = injector_ ? injector_->patches().count(addr) > 0
                              : patchBackups_.find(addr) != patchBackups_.end();
    if (hasPatch) {
        restoreAction = menu.addAction("Restore original instruction");
    }

    QAction *chosen = menu.exec(disasmTable_->viewport()->mapToGlobal(pos));
    if (!chosen) return;
    // Re-fetch current values in case view changed while menu was open.
    addrItem = disasmTable_->item(row, 0);
    bytesItem = disasmTable_->item(row, 1);
    opItem = disasmTable_->item(row, 2);

    if (chosen == copyAddr && addrItem) {
        copyToClipboard(addrItem->text());
    } else if (chosen == copyBytes && bytesItem) {
        copyToClipboard(bytesItem->text());
    } else if (chosen == copyInstr && opItem) {
        copyToClipboard(opItem->text());
    } else if (chosen == nopOut && bytesItem) {
        QStringList parts = bytesItem->text().split(' ', Qt::SkipEmptyParts);
        QString nops;
        for (int i = 0; i < parts.size(); ++i) nops += "90 ";
        patchBytes(addr, nops.trimmed());
    } else if (chosen == patch && bytesItem) {
        patchBytes(addr, bytesItem->text());
    } else if (chosen == restoreAction) {
        restorePatchedBytes(addr);
    }
}

void MemoryViewerWindow::onRegionContextMenu(const QPoint &pos) {
    auto *item = regionTable_->itemAt(pos);
    if (!item) return;
    int row = item->row();
    auto *startItem = regionTable_->item(row, 0);
    auto *endItem = regionTable_->item(row, 1);
    auto *permItem = regionTable_->item(row, 2);
    auto *fileItem = regionTable_->item(row, 4);

    QMenu menu(this);
    QAction *copyStart = menu.addAction("Copy start");
    QAction *copyEnd = menu.addAction("Copy end");
    QAction *copyPerms = menu.addAction("Copy perms");
    QAction *copyPath = menu.addAction("Copy path");
    QAction *jump = menu.addAction("Jump to region");

    QAction *chosen = menu.exec(regionTable_->viewport()->mapToGlobal(pos));
    if (!chosen) return;
    // Refresh pointers in case of table update while menu open.
    startItem = regionTable_->item(row, 0);
    endItem = regionTable_->item(row, 1);
    permItem = regionTable_->item(row, 2);
    fileItem = regionTable_->item(row, 4);

    if (chosen == copyStart && startItem) copyToClipboard(startItem->text());
    else if (chosen == copyEnd && endItem) copyToClipboard(endItem->text());
    else if (chosen == copyPerms && permItem) copyToClipboard(permItem->text());
    else if (chosen == copyPath && fileItem) copyToClipboard(fileItem->text());
    else if (chosen == jump && startItem) {
        bool ok = false;
        uintptr_t addr = startItem->text().toULongLong(&ok, 0);
        if (ok) jumpTo(addr);
    }
}

void MemoryViewerWindow::setAutoRefresh(bool enabled) {
    if (enabled && proc_ && proc_->isAttached()) {
        refreshTimer_->start(refreshIntervalSpin_->value());
    } else {
        refreshTimer_->stop();
    }
}
