#include "gui/AutoAssemblerDialog.h"

#include "core/AutoAssembler.h"
#include "core/CodeInjector.h"
#include "core/TargetProcess.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QMessageBox>
#include <QTextEdit>
#include <QLineEdit>
#include <QSpinBox>
#include <QGroupBox>
#include <QGridLayout>
#include <QStringList>
#include <QToolButton>
#include <QMenu>

AutoAssemblerDialog::AutoAssemblerDialog(core::CodeInjector *injector, QWidget *parent)
    : QDialog(parent), injector_(injector) {
    setWindowTitle("Auto Assembler");
    auto *layout = new QVBoxLayout(this);
    layout->addWidget(new QLabel("Syntax: 'patch <addr> <hex bytes...>' or 'restore <addr>'.\nUse [ENABLE]/[DISABLE] sections.", this));

    auto *templateBox = new QGroupBox("Code Injection Template", this);
    auto *templateLayout = new QGridLayout;
    templateAddressEdit_ = new QLineEdit(this);
    templateAddressEdit_->setPlaceholderText("0x0");
    templateSizeSpin_ = new QSpinBox(this);
    templateSizeSpin_->setRange(5, 32);
    templateSizeSpin_->setValue(5);
    templateHint_ = new QLabel("Use templates for ComfyEngine-style code/AoB injections.", this);
    templateButton_ = new QToolButton(this);
    templateButton_->setText("Templates");
    templateButton_->setPopupMode(QToolButton::MenuButtonPopup);
    templateMenu_ = new QMenu(templateButton_);
    auto codeAct = templateMenu_->addAction("Code Injection");
    codeAct->setData(static_cast<int>(TemplateKind::CodeInjection));
    auto aobAct = templateMenu_->addAction("AoB Injection");
    aobAct->setData(static_cast<int>(TemplateKind::AobInjection));
    auto emptyAct = templateMenu_->addAction("Empty Script");
    emptyAct->setData(static_cast<int>(TemplateKind::Empty));
    templateButton_->setMenu(templateMenu_);
    templateLayout->addWidget(new QLabel("Address", this), 0, 0);
    templateLayout->addWidget(templateAddressEdit_, 0, 1);
    templateLayout->addWidget(new QLabel("Bytes to replace", this), 1, 0);
    templateLayout->addWidget(templateSizeSpin_, 1, 1);
    templateLayout->addWidget(templateButton_, 2, 0, 1, 2);
    templateLayout->addWidget(templateHint_, 3, 0, 1, 2);
    templateBox->setLayout(templateLayout);
    layout->addWidget(templateBox);

    auto *scriptRow = new QHBoxLayout;
    scriptNameEdit_ = new QLineEdit(this);
    scriptNameEdit_->setPlaceholderText("Script description");
    addToTableBtn_ = new QPushButton("Add to Cheat Table", this);
    scriptRow->addWidget(scriptNameEdit_);
    scriptRow->addWidget(addToTableBtn_);
    layout->addLayout(scriptRow);

    editor_ = new QPlainTextEdit(this);
    editor_->setPlaceholderText("patch 0x401000 90 90 90\nrestore 0x401000");
    layout->addWidget(editor_);

    auto *btnRow = new QHBoxLayout;
    enableBtn_ = new QPushButton("Enable", this);
    disableBtn_ = new QPushButton("Disable", this);
    btnRow->addWidget(enableBtn_);
    btnRow->addWidget(disableBtn_);
    btnRow->addStretch();
    layout->addLayout(btnRow);

    statusLabel_ = new QLabel("Idle", this);
    layout->addWidget(statusLabel_);

    log_ = new QTextEdit(this);
    log_->setReadOnly(true);
    log_->setFixedHeight(120);
    layout->addWidget(log_);

    if (injector_) {
        engine_ = std::make_unique<core::AutoAssembler>(*injector_);
    }

    connect(enableBtn_, &QPushButton::clicked, this, &AutoAssemblerDialog::onEnable);
    connect(disableBtn_, &QPushButton::clicked, this, &AutoAssemblerDialog::onDisable);
    connect(templateButton_, &QToolButton::clicked, this, &AutoAssemblerDialog::onGenerateTemplate);
    connect(templateMenu_, &QMenu::triggered, this, [this](QAction *act) {
        insertTemplate(static_cast<TemplateKind>(act->data().toInt()));
    });
    connect(addToTableBtn_, &QPushButton::clicked, this, &AutoAssemblerDialog::onAddToTable);
}

void AutoAssemblerDialog::setStatus(const QString &text, bool ok) {
    statusLabel_->setText(text);
    statusLabel_->setStyleSheet(ok ? "color: green;" : "color: red;");
    if (!ok) {
        log_->append(text);
    }
}

void AutoAssemblerDialog::onEnable() {
    if (!injector_ || !engine_) {
        setStatus("No injector set", false);
        return;
    }
    std::vector<std::string> errors;
    std::vector<std::string> logs;
    auto scriptOpt = engine_->parse(core::AutoAssembler::ensureEnableSection(buildScriptFromEditor().toStdString()),
                                    errors, &logs);
    log_->clear();
    for (const auto &entry : logs) {
        log_->append(QString::fromStdString(entry));
    }
    for (const auto &err : errors) {
        log_->append(QString::fromStdString(err));
    }
    if (!errors.empty()) {
        setStatus("Parse errors", false);
        return;
    }
    if (!scriptOpt || (scriptOpt->enableCmds.empty() && scriptOpt->disableCmds.empty())) {
        setStatus("No commands found", false);
        return;
    }
    engine_->apply(scriptOpt->enableCmds);
    lastEnable_ = scriptOpt->enableCmds;
    lastDisable_ = scriptOpt->disableCmds;
    enabled_ = true;
    setStatus("Enabled", true);
}

void AutoAssemblerDialog::onDisable() {
    if (!injector_ || !engine_) {
        setStatus("No injector set", false);
        return;
    }
    if (!enabled_) {
        setStatus("Script not enabled", false);
        return;
    }
    if (!lastDisable_.empty()) {
        engine_->apply(lastDisable_);
    } else {
        engine_->restore(lastEnable_);
    }
    enabled_ = false;
    setStatus("Disabled", true);
}

bool AutoAssemblerDialog::executeScriptText(const QString &script, bool enable, QString *logOut) {
    if (!injector_ || !engine_) return false;
    core::AutoAssembler runner(*injector_);
    std::vector<std::string> errors;
    auto parsed = runner.parse(script.toStdString(), errors);
    if (!errors.empty()) {
        if (logOut) {
            QStringList list;
            for (const auto &err : errors) list << QString::fromStdString(err);
            *logOut = list.join('\n');
        }
        return false;
    }
    if (!parsed) return false;
    if (enable) {
        runner.apply(parsed->enableCmds);
    } else {
        if (!parsed->disableCmds.empty()) {
            runner.apply(parsed->disableCmds);
        } else {
            runner.restore(parsed->enableCmds);
        }
    }
    return true;
}

void AutoAssemblerDialog::setInjectionContext(uintptr_t address, const std::vector<uint8_t> &originalBytes) {
    templateAddress_ = address;
    templateBytes_ = originalBytes;
    if (address != 0) {
        templateAddressEdit_->setText(QString::asprintf("0x%llx", static_cast<unsigned long long>(address)));
        if (scriptNameEdit_ && scriptNameEdit_->text().isEmpty()) {
            scriptNameEdit_->setText(QString("Script %1").arg(QString::number(address, 16)));
        }
    }
    if (!templateBytes_.empty()) {
        templateSizeSpin_->setValue(static_cast<int>(templateBytes_.size()));
    }
}

void AutoAssemblerDialog::setScriptForEditing(const QString &name, const QString &script) {
    if (scriptNameEdit_) scriptNameEdit_->setText(name);
    if (editor_) editor_->setPlainText(script);
}

std::vector<uint8_t> AutoAssemblerDialog::ensureTemplateBytes(uintptr_t address) const {
    std::vector<uint8_t> bytes = templateBytes_;
    if (bytes.empty()) {
        int count = templateSizeSpin_ ? templateSizeSpin_->value() : 5;
        if (count < 5) count = 5;
        bytes.resize(static_cast<size_t>(count));
        if (!injector_ || !injector_->target().readMemory(address, bytes.data(), bytes.size())) {
            bytes.clear();
        }
    }
    return bytes;
}

void AutoAssemblerDialog::insertTemplate(TemplateKind kind) {
    uintptr_t address = templateAddress_;
    if (address == 0) {
        bool ok = false;
        address = templateAddressEdit_->text().trimmed().toULongLong(&ok, 0);
        if (!ok || address == 0) {
            setStatus("Invalid address for template.", false);
            return;
        }
    }

    auto bytes = ensureTemplateBytes(address);
    if ((kind != TemplateKind::Empty) && bytes.empty()) {
        setStatus("Failed to read bytes for template.", false);
        return;
    }

    QString script;
    switch (kind) {
        case TemplateKind::CodeInjection: {
            if (bytes.size() < 5) {
                setStatus("Need at least 5 bytes for code injection.", false);
                return;
            }
            script = QString::fromStdString(core::AutoAssembler::codeInjectionTemplate(address, bytes));
            break;
        }
        case TemplateKind::AobInjection:
            script = QString::fromStdString(core::AutoAssembler::aobInjectionTemplate(bytes));
            break;
        case TemplateKind::Empty:
            script = QString::fromStdString(core::AutoAssembler::emptyTemplate());
            break;
    }

    editor_->setPlainText(script);
    setStatus("Template generated.", true);
}

void AutoAssemblerDialog::onGenerateTemplate() {
    insertTemplate(TemplateKind::CodeInjection);
}

QString AutoAssemblerDialog::buildScriptFromEditor() const {
    QString script = editor_ ? editor_->toPlainText().trimmed() : QString();
    if (script.isEmpty()) return script;
    if (!script.contains("[ENABLE]", Qt::CaseInsensitive)) {
        script = QString("[ENABLE]\n%1\n\n[DISABLE]\n").arg(script);
    }
    return script;
}

void AutoAssemblerDialog::onAddToTable() {
    QString script = buildScriptFromEditor().trimmed();
    if (script.isEmpty()) {
        QMessageBox::warning(this, "Auto Assembler", "Script is empty.");
        return;
    }
    QString name = scriptNameEdit_ ? scriptNameEdit_->text().trimmed() : QString();
    if (name.isEmpty()) {
        name = templateAddress_ ? QString("Script %1").arg(QString::number(templateAddress_, 16))
                                : QStringLiteral("Auto Script");
    }
    emit scriptReady(name, script);
    setStatus("Script sent to table", true);
}
