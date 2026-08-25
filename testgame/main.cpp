#include <QApplication>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QPushButton>
#include <QGroupBox>
#include <QTimer>
#include <QString>
#include <cstdlib>
#include <cstring>
#include <atomic>
#include <random>

#include <sys/prctl.h>

struct Inventory {
    volatile int ammo{30};
    volatile int grenades{3};
    volatile int money{5000};
};

struct Player {
    volatile int health{100};
    volatile float speed{1.0f};
    volatile double stamina{75.0};
    Inventory inv;
};

struct PtrNode {
    volatile int value{0};
    PtrNode *next{nullptr};
};

static Player player;
static PtrNode baseNode;
static PtrNode midNode;
static PtrNode tailNode;
static int secretValue = 1337;
class GameWidget : public QWidget {
    Q_OBJECT
public:
    GameWidget(QWidget *parent = nullptr) : QWidget(parent) {
        setupPointerChain();
        setupUi();
        setupTimer();
    }

private:
    QLabel *healthLabel_;
    QLabel *speedLabel_;
    QLabel *staminaLabel_;
    QLabel *ammoLabel_;
    QLabel *grenadesLabel_;
    QLabel *moneyLabel_;
    QLabel *ptrChainLabel_;

    void setupPointerChain() {
        baseNode.value = 111;
        midNode.value = 222;
        tailNode.value = 333;
        baseNode.next = &midNode;
        midNode.next = &tailNode;
        tailNode.next = reinterpret_cast<PtrNode *>(&secretValue);
    }

    void setupUi() {
        auto *root = new QVBoxLayout(this);

        auto *statsBox = new QGroupBox("Player Stats", this);
        auto *grid = new QGridLayout(statsBox);
        healthLabel_ = addRow(grid, 0, "Health");
        speedLabel_ = addRow(grid, 1, "Speed");
        staminaLabel_ = addRow(grid, 2, "Stamina");
        ammoLabel_ = addRow(grid, 3, "Ammo");
        grenadesLabel_ = addRow(grid, 4, "Grenades");
        moneyLabel_ = addRow(grid, 5, "Money");
        root->addWidget(statsBox);

        auto *btnRow = new QHBoxLayout;
        QPushButton *btnDamage = new QPushButton("-10 Health", this);
        QPushButton *btnHeal = new QPushButton("+10 Health", this);
        QPushButton *btnSpendAmmo = new QPushButton("-5 Ammo", this);
        QPushButton *btnAddMoney = new QPushButton("+500 Money", this);
        QPushButton *btnShuffle = new QPushButton("Shuffle Pointers", this);
        btnRow->addWidget(btnDamage);
        btnRow->addWidget(btnHeal);
        btnRow->addWidget(btnSpendAmmo);
        btnRow->addWidget(btnAddMoney);
        btnRow->addWidget(btnShuffle);
        root->addLayout(btnRow);

        auto *ptrBox = new QGroupBox("Pointer Chain", this);
        auto *ptrLayout = new QVBoxLayout(ptrBox);
        ptrChainLabel_ = new QLabel(ptrBox);
        ptrChainLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        ptrLayout->addWidget(ptrChainLabel_);
        ptrBox->setLayout(ptrLayout);
        root->addWidget(ptrBox);

        connect(btnDamage, &QPushButton::clicked, this, [this]() {
            player.health -= 10;
        });
        connect(btnHeal, &QPushButton::clicked, this, [this]() {
            player.health += 10;
        });
        connect(btnSpendAmmo, &QPushButton::clicked, this, [this]() {
            player.inv.ammo -= 5;
        });
        connect(btnAddMoney, &QPushButton::clicked, this, [this]() {
            player.inv.money += 500;
        });
        connect(btnShuffle, &QPushButton::clicked, this, [this]() {
            shufflePointers();
        });

        setLayout(root);
        updateLabels();
    }

    QLabel* addRow(QGridLayout *grid, int row, const QString &name) {
        grid->addWidget(new QLabel(name + ":", this), row, 0);
        auto *val = new QLabel(this);
        val->setTextInteractionFlags(Qt::TextSelectableByMouse);
        grid->addWidget(val, row, 1);
        return val;
    }

    void setupTimer() {
        auto *timer = new QTimer(this);
        connect(timer, &QTimer::timeout, this, [this]() {
            updateLabels();
        });
        timer->start(200);
    }

    void shufflePointers() {
        static std::mt19937 rng{std::random_device{}()};
        std::uniform_int_distribution<int> distVal(100, 1000);
        std::uniform_int_distribution<int> distSecret(1000, 5000);
        baseNode.value = distVal(rng);
        midNode.value = distVal(rng);
        tailNode.value = distVal(rng);
        secretValue = distSecret(rng);
    }

    void updateLabels() {
        healthLabel_->setText(QString::number(player.health));
        speedLabel_->setText(QString::number(player.speed, 'f', 2));
        staminaLabel_->setText(QString::number(player.stamina, 'f', 2));
        ammoLabel_->setText(QString::number(player.inv.ammo));
        grenadesLabel_->setText(QString::number(player.inv.grenades));
        moneyLabel_->setText(QString::number(player.inv.money));
        QString ptrInfo;
        ptrInfo += QString("baseNode @ %1 value=%2\n").arg((quintptr)&baseNode, 0, 16).arg(baseNode.value);
        ptrInfo += QString("midNode  @ %1 value=%2\n").arg((quintptr)&midNode, 0, 16).arg(midNode.value);
        ptrInfo += QString("tailNode @ %1 value=%2\n").arg((quintptr)&tailNode, 0, 16).arg(tailNode.value);
        ptrInfo += QString("secret   @ %1 value=%2\n").arg((quintptr)&secretValue, 0, 16).arg(secretValue);
        ptrChainLabel_->setText(ptrInfo);
    }
};

int main(int argc, char **argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--allow-ptrace") {
            prctl(PR_SET_PTRACER, -1UL);
        }
    }
    QApplication app(argc, argv);
    GameWidget w;
    w.setWindowTitle("ComfyEngine Mini Tutorial Game");
    w.resize(600, 400);
    w.show();
    return app.exec();
}

#include "main.moc"
