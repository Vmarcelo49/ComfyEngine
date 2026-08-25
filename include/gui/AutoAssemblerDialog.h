#pragma once

#include "core/AutoAssembler.h"

#include <QDialog>
#include <memory>
#include <vector>
#include <cstdint>

class QPlainTextEdit;
class QPushButton;
class QLabel;
class QTextEdit;
class QLineEdit;
class QSpinBox;
class QToolButton;
class QMenu;

namespace core {
class CodeInjector;
}

class AutoAssemblerDialog : public QDialog {
    Q_OBJECT
public:
    AutoAssemblerDialog(core::CodeInjector *injector, QWidget *parent = nullptr);
    void setInjectionContext(uintptr_t address, const std::vector<uint8_t> &originalBytes);
    void setScriptForEditing(const QString &name, const QString &script);
    bool executeScriptText(const QString &script, bool enable, QString *logOut = nullptr);

signals:
    void scriptReady(const QString &name, const QString &scriptText);

private slots:
    void onEnable();
    void onDisable();
    void onGenerateTemplate();
    void onAddToTable();

private:
    core::CodeInjector *injector_{};
    std::unique_ptr<core::AutoAssembler> engine_;
    QPlainTextEdit *editor_{};
    QPushButton *enableBtn_{};
    QPushButton *disableBtn_{};
    QToolButton *templateButton_{};
    QMenu *templateMenu_{};
    QPushButton *addToTableBtn_{};
    QLineEdit *scriptNameEdit_{};
    QLabel *statusLabel_{};
    QTextEdit *log_{};
    QLineEdit *templateAddressEdit_{};
    QSpinBox *templateSizeSpin_{};
    QLabel *templateHint_{};
    uintptr_t templateAddress_{0};
    std::vector<uint8_t> templateBytes_;

    bool enabled_{false};

    using CommandList = std::vector<core::AutoAssembler::Command>;
    CommandList lastEnable_;
    CommandList lastDisable_;

    enum class TemplateKind { CodeInjection, AobInjection, Empty };
    void insertTemplate(TemplateKind kind);
    void setStatus(const QString &text, bool ok);
    std::vector<uint8_t> ensureTemplateBytes(uintptr_t address) const;
    QString buildScriptFromEditor() const;
};
