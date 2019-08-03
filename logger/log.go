package logger

import "github.com/TykTechnologies/logrus"

type Entry = *logrus.Entry

func GetLogger(modName string) Entry {
	log := logrus.WithField("app", "tk8s").WithField("mod", modName)
	return log
}
